use lexopt::prelude::*;
use paranoid_audit::{
    AuditEvent, AuditSinkHealth, AuditTrail, assess_optional_jsonl_file_audit_sink,
    write_events_jsonl,
};
use paranoid_core::{
    CharsetSpec, FrameworkId, GenerationReport, ParanoidError, ParanoidRequest, VERSION,
    secure_preview,
};
use paranoid_ops::{
    GeneratePasswordError, GeneratePasswordOperation, GeneratePasswordOutcome, OpsCommand,
    OpsCommandEnvelope, OpsPolicyContext, OpsPolicyDecision, OpsProfile,
    collect_federal_startup_evidence_with_audit_sink, evaluate_policy, record_ops_request,
    record_ops_response, run_generate_password_operation,
};
use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 1;
const EX_CSPRNG: i32 = 2;
const EX_AUDIT_FAIL: i32 = 3;
const EX_INTERNAL: i32 = 4;
const EX_CONSTRAINTS: i32 = 5;
const EX_POLICY_DENY: i32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    Auto,
    Cli,
    Tui,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone)]
struct CliOptions {
    request: ParanoidRequest,
    audit: bool,
    quiet: bool,
    mode: LaunchMode,
    output: OutputFormat,
    profile: OpsProfile,
    audit_jsonl: Option<PathBuf>,
    require_audit_sink: bool,
    federal_evidence: bool,
    detect_environment: bool,
    explicit_operational_flag: bool,
}

enum ParseOutcome {
    Run(CliOptions),
    Exit(i32),
}

impl Default for CliOptions {
    fn default() -> Self {
        Self {
            request: ParanoidRequest::default(),
            audit: true,
            quiet: false,
            mode: LaunchMode::Auto,
            output: OutputFormat::Text,
            profile: OpsProfile::Default,
            audit_jsonl: None,
            require_audit_sink: false,
            federal_evidence: false,
            detect_environment: false,
            explicit_operational_flag: false,
        }
    }
}

fn main() {
    // P9.3: disable core dumps and deny same-user debugger/crash-dump
    // attachment before any secret material (master password, derived KEK,
    // vault master key) is ever read into memory. Best-effort — see
    // `paranoid_vault::harden_process_memory` for the per-platform outcome
    // semantics; a sandboxed environment that can't apply this still runs.
    paranoid_vault::harden_process_memory();
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    let exit_code = match try_main(raw_args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            EX_INTERNAL
        }
    };
    std::process::exit(exit_code);
}

fn try_main(raw_args: Vec<OsString>) -> anyhow::Result<i32> {
    if matches!(raw_args.get(1).and_then(|arg| arg.to_str()), Some("vault")) {
        return paranoid_cli::vault_cli::run(&raw_args[2..]);
    }

    let options = match parse_args(raw_args)? {
        ParseOutcome::Run(options) => options,
        ParseOutcome::Exit(code) => return Ok(code),
    };
    let interactive = (io::stdin().is_terminal() && io::stdout().is_terminal())
        || paranoid_cli::scripted::is_script_active();
    let launch_tui = should_launch_tui(&options, interactive);
    let audit_sink_health = assess_optional_jsonl_file_audit_sink(options.audit_jsonl.as_deref());

    if options.federal_evidence {
        let evidence = collect_federal_startup_evidence_with_audit_sink(
            options.profile,
            audit_sink_health,
            option_env!("PARANOID_CLI_BUILD_COMMIT").unwrap_or("dev"),
            option_env!("PARANOID_CLI_BUILD_DATE").unwrap_or("dev"),
        );
        print_federal_evidence_json(&evidence)?;
        return Ok(EX_OK);
    }

    if options.detect_environment {
        let report = paranoid_cli::capability_detect::collect_capability_report(
            &paranoid_vault::default_vault_path(),
        );
        print_capability_report_json(&report)?;
        return Ok(EX_OK);
    }

    if launch_tui {
        return paranoid_cli::tui::run().map(|_| EX_OK);
    }

    let envelope = OpsCommandEnvelope::local(
        paranoid_audit::AuditSurface::Cli,
        options.profile,
        OpsCommand::GeneratePassword,
    );
    let context = OpsPolicyContext {
        profile: options.profile,
        audit_sink_required: options.audit_jsonl.is_some()
            || options.require_audit_sink
            || options.profile == OpsProfile::FederalReady,
        audit_sink_available: audit_sink_health.is_available(),
        crypto_provider: paranoid_ops::FederalCryptoProviderEvidence::collect_from_environment(),
        seal_posture: None,
    };
    let mut policy_trail = AuditTrail::for_operation(envelope.operation_id.clone());
    record_ops_request(&mut policy_trail, &envelope);
    let policy_decision = evaluate_policy(&envelope, &context);
    record_ops_response(&mut policy_trail, &envelope, &policy_decision);

    if !policy_decision.is_allowed() {
        let audit_events = policy_trail.into_events();
        write_optional_audit_jsonl(&options.audit_jsonl, &audit_sink_health, &audit_events)?;
        if options.output == OutputFormat::Json {
            print_policy_denial_json(
                &envelope.operation_id,
                &policy_decision,
                &audit_sink_health,
                &audit_events,
            )?;
        } else {
            eprintln!("policy: {}", policy_denial_message(&policy_decision));
        }
        return Ok(EX_POLICY_DENY);
    }

    let operation = GeneratePasswordOperation {
        operation_id: envelope.operation_id.clone(),
        request: options.request.clone(),
        audit: options.audit,
    };

    let outcome = match run_generate_password_operation(operation) {
        Ok(outcome) => outcome,
        Err(error) => {
            let mut audit_events = policy_trail.into_events();
            audit_events.extend_from_slice(error.audit_events());
            write_optional_audit_jsonl(&options.audit_jsonl, &audit_sink_health, &audit_events)?;
            if options.output == OutputFormat::Json {
                print_generation_error_json(&error)?;
            } else {
                eprintln!("error: {error}");
            }
            return Ok(map_error_to_exit_code(error.source()));
        }
    };
    let mut audit_events = policy_trail.into_events();
    audit_events.extend_from_slice(&outcome.audit_events);
    let outcome = GeneratePasswordOutcome {
        operation_id: outcome.operation_id,
        report: outcome.report,
        audit_events,
    };
    write_optional_audit_jsonl(
        &options.audit_jsonl,
        &audit_sink_health,
        &outcome.audit_events,
    )?;

    if options.output == OutputFormat::Json {
        print_generation_json(&outcome)?;
    } else {
        print_passwords(&outcome.report)?;
    }
    if options.audit {
        if !options.quiet && options.output == OutputFormat::Text {
            print_audit(&outcome.report)?;
        }
        if outcome
            .report
            .audit
            .as_ref()
            .is_some_and(|audit| !audit.overall_pass)
        {
            return Ok(EX_AUDIT_FAIL);
        }
    } else if !options.quiet && options.output == OutputFormat::Text {
        eprintln!("audit: skipped");
    }

    Ok(EX_OK)
}

fn should_launch_tui(options: &CliOptions, interactive: bool) -> bool {
    matches!(options.mode, LaunchMode::Tui)
        || (matches!(options.mode, LaunchMode::Auto)
            && interactive
            && !options.explicit_operational_flag)
}

fn parse_args(args: Vec<OsString>) -> anyhow::Result<ParseOutcome> {
    let mut parser = lexopt::Parser::from_args(args.into_iter().skip(1));
    let mut options = CliOptions::default();
    let mut charset_spec: Option<String> = None;

    while let Some(argument) = parser.next()? {
        match argument {
            Short('l') | Long("length") => {
                options.request.length = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Short('c') | Long("count") => {
                options.request.count = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Short('s') | Long("charset") => {
                charset_spec = Some(parser.value()?.string()?);
                options.explicit_operational_flag = true;
            }
            Long("batch-size") => {
                options.request.batch_size = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Long("require-lower") => {
                options.request.requirements.min_lowercase = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Long("require-upper") => {
                options.request.requirements.min_uppercase = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Long("require-digit") => {
                options.request.requirements.min_digits = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Long("require-symbol") => {
                options.request.requirements.min_symbols = parser.value()?.string()?.parse()?;
                options.explicit_operational_flag = true;
            }
            Long("framework") => {
                let raw = parser.value()?.string()?;
                for item in raw
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    let framework = FrameworkId::parse(item)
                        .ok_or_else(|| anyhow::anyhow!("unknown framework: {item}"))?;
                    if !options.request.selected_frameworks.contains(&framework) {
                        options.request.selected_frameworks.push(framework);
                    }
                }
                options.explicit_operational_flag = true;
            }
            Long("no-audit") => {
                options.audit = false;
                options.explicit_operational_flag = true;
            }
            Long("quiet") => {
                options.quiet = true;
                options.explicit_operational_flag = true;
            }
            Long("json") => {
                options.output = OutputFormat::Json;
                options.explicit_operational_flag = true;
            }
            Long("profile") => {
                options.profile = parse_ops_profile(&parser.value()?.string()?)?;
                options.explicit_operational_flag = true;
            }
            // brand.md §3c: the user-facing surface names this
            // `--assurance strict` ("apply the strictest audit and evidence
            // rules") rather than the internal `federal-ready` profile name.
            // `--federal-ready` keeps working unchanged for existing scripts.
            Long("assurance") => {
                let value = parser.value()?.string()?;
                if value != "strict" {
                    return Err(anyhow::anyhow!(
                        "unknown assurance level: {value} (expected: strict)"
                    ));
                }
                options.profile = OpsProfile::FederalReady;
                options.require_audit_sink = true;
                options.explicit_operational_flag = true;
            }
            Long("federal-ready") => {
                options.profile = OpsProfile::FederalReady;
                options.require_audit_sink = true;
                options.explicit_operational_flag = true;
            }
            Long("audit-jsonl") => {
                options.audit_jsonl = Some(PathBuf::from(parser.value()?.string()?));
                options.explicit_operational_flag = true;
            }
            Long("require-audit-sink") => {
                options.require_audit_sink = true;
                options.explicit_operational_flag = true;
            }
            // brand.md §3c/§4: user-facing name for `--federal-evidence` is
            // "Evidence bundle" — `--evidence` is the documented spelling;
            // `--federal-evidence` keeps working unchanged.
            Long("evidence") | Long("federal-evidence") => {
                options.federal_evidence = true;
                options.output = OutputFormat::Json;
                options.profile = OpsProfile::FederalReady;
                options.require_audit_sink = true;
                options.explicit_operational_flag = true;
            }
            Long("detect-environment") => {
                options.detect_environment = true;
                options.output = OutputFormat::Json;
                options.explicit_operational_flag = true;
            }
            Long("tui") => options.mode = LaunchMode::Tui,
            Long("cli") => options.mode = LaunchMode::Cli,
            Short('V') | Long("version") => {
                print_version();
                return Ok(ParseOutcome::Exit(EX_OK));
            }
            Short('h') | Long("help") => {
                print_usage(io::stdout())?;
                return Ok(ParseOutcome::Exit(EX_OK));
            }
            Value(value) => {
                return Err(anyhow::anyhow!(
                    "unexpected positional argument: {}",
                    value.to_string_lossy()
                ));
            }
            _ => return Err(anyhow::anyhow!("unsupported argument")),
        }
    }

    if let Some(charset) = charset_spec {
        options.request.charset = CharsetSpec::NamedOrLiteral(charset);
    }

    Ok(ParseOutcome::Run(options))
}

fn parse_ops_profile(raw: &str) -> anyhow::Result<OpsProfile> {
    match raw {
        "default" => Ok(OpsProfile::Default),
        "federal-ready" | "federal_ready" => Ok(OpsProfile::FederalReady),
        other => Err(anyhow::anyhow!("unknown profile: {other}")),
    }
}

fn print_usage(mut out: impl Write) -> io::Result<()> {
    writeln!(
        out,
        "\
Usage: paranoid-passwd [OPTIONS]
       paranoid-passwd vault [OPTIONS] [SUBCOMMAND]

Generate cryptographically strong passwords with a self-audit.

Modes:
  --tui                    Force the full-screen wizard
  --cli                    Force scriptable CLI mode even on an interactive TTY

Generation:
  -l, --length N           Password length (1..256, default 32)
  -c, --count N            Number of passwords (1..10, default 1)
  -s, --charset SET        Charset name or literal (alnum | alnum-symbols | full | hex)
      --batch-size N       Audit batch size (1..2000, default 500)
      --require-lower N    Minimum lowercase characters
      --require-upper N    Minimum uppercase characters
      --require-digit N    Minimum digit characters
      --require-symbol N   Minimum symbol characters
      --framework ID       Compliance framework (repeat or comma-separate):
                           nist, pci_dss, hipaa, soc2, gdpr, iso27001

Output:
      --json               Emit a structured JSON operation report on stdout
      --audit-jsonl PATH   Append redacted audit events to a JSONL sink
      --require-audit-sink Fail closed unless --audit-jsonl is writable
      --assurance strict   Apply the strictest audit and evidence rules
                           (alias: --federal-ready; --profile federal-ready)
      --evidence           Produce a signed, timestamped evidence bundle as JSON
                           you can hand to a lawyer, auditor, or court
                           (alias: --federal-evidence)
      --detect-environment Emit OS keychain, clipboard, display server, and
                           hardware-protection capability evidence as JSON
      --no-audit           Skip the statistical audit
      --quiet              Suppress audit stage output on stderr
  -V, --version            Print version info and exit
  -h, --help               Print this help and exit

Vault:
  vault                    Manage the local encrypted vault; defaults to the vault TUI on an interactive terminal when no subcommand is passed

Behavior:
  When attached to a TTY with no mode-forcing or operational flags, paranoid-passwd
  launches the wizard TUI. In non-interactive contexts it keeps the scriptable CLI.
"
    )
}

fn print_version() {
    println!("paranoid-passwd {VERSION}");
    println!(
        "build:          {}",
        option_env!("PARANOID_CLI_BUILD_DATE").unwrap_or("dev")
    );
    println!(
        "commit:         {}",
        option_env!("PARANOID_CLI_BUILD_COMMIT").unwrap_or("dev")
    );
    println!("sha256:         OpenSSL-backed");
    println!("rng:            OpenSSL RAND_bytes");
}

fn print_passwords(report: &GenerationReport) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    for password in &report.passwords {
        writeln!(handle, "{}", password.value)?;
    }
    handle.flush()
}

fn print_generation_json(outcome: &GeneratePasswordOutcome) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, &outcome.automation_report())
        .map_err(io::Error::other)?;
    writeln!(handle)?;
    handle.flush()
}

fn print_generation_error_json(error: &GeneratePasswordError) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, &error.failure_report()).map_err(io::Error::other)?;
    writeln!(handle)?;
    handle.flush()
}

fn print_federal_evidence_json(evidence: &paranoid_ops::FederalStartupEvidence) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, evidence).map_err(io::Error::other)?;
    writeln!(handle)?;
    handle.flush()
}

fn print_capability_report_json(report: &paranoid_ops::CapabilityReport) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, report).map_err(io::Error::other)?;
    writeln!(handle)?;
    handle.flush()
}

fn print_policy_denial_json(
    operation_id: &str,
    decision: &OpsPolicyDecision,
    audit_sink: &AuditSinkHealth,
    audit_events: &[AuditEvent],
) -> io::Result<()> {
    let report = serde_json::json!({
        "schema_version": paranoid_audit::AUDIT_SCHEMA_VERSION,
        "operation": "generate_password",
        "operation_id": operation_id,
        "status": "error",
        "error_kind": "policy_denied",
        "error_message": policy_denial_message(decision),
        "policy_decision": decision,
        "audit_sink": audit_sink,
        "audit_events": audit_events,
    });
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, &report).map_err(io::Error::other)?;
    writeln!(handle)?;
    handle.flush()
}

fn write_optional_audit_jsonl(
    path: &Option<PathBuf>,
    audit_sink: &AuditSinkHealth,
    audit_events: &[AuditEvent],
) -> anyhow::Result<()> {
    if let Some(path) = path
        && audit_sink.is_available()
    {
        write_events_jsonl(path, audit_events)?;
    }
    Ok(())
}

fn policy_denial_message(decision: &OpsPolicyDecision) -> String {
    match decision {
        OpsPolicyDecision::Deny {
            reason,
            missing_controls,
        } => {
            if missing_controls.is_empty() {
                reason.clone()
            } else {
                format!("{reason}: {}", missing_controls.join(", "))
            }
        }
        OpsPolicyDecision::Challenge {
            reason,
            required_actions,
            ..
        } => {
            if required_actions.is_empty() {
                reason.clone()
            } else {
                format!("{reason}: {}", required_actions.join(", "))
            }
        }
        OpsPolicyDecision::Allow { reason } => reason.clone(),
    }
}

fn print_audit(report: &GenerationReport) -> io::Result<()> {
    let Some(audit) = &report.audit else {
        return Ok(());
    };

    let stderr = io::stderr();
    let mut handle = stderr.lock();
    writeln!(
        handle,
        "[1/7] generate          OK  {} password(s) x {} chars",
        report.passwords.len(),
        audit.password_length
    )?;
    if audit.passwords_all_pass {
        writeln!(
            handle,
            "[2/7] per-password      OK  all emitted passwords passed pattern + selected-framework checks"
        )?;
    } else {
        let flagged = report
            .passwords
            .iter()
            .filter(|password| !password.all_pass)
            .count();
        writeln!(
            handle,
            "[2/7] per-password      FAIL  {flagged} emitted password(s) flagged for review"
        )?;
    }
    if audit.chi2_pass {
        writeln!(
            handle,
            "[3/7] chi-squared       OK  chi2={:.2} df={} p={:.4}",
            audit.chi2_statistic, audit.chi2_df, audit.chi2_p_value
        )?;
    } else {
        writeln!(handle, "[3/7] chi-squared       FAIL  p-value <= 0.01")?;
    }
    if audit.serial_pass {
        writeln!(
            handle,
            "[4/7] serial-corr       OK  r={:.4}",
            audit.serial_correlation
        )?;
    } else {
        writeln!(handle, "[4/7] serial-corr       FAIL  |r| >= 0.05")?;
    }
    if audit.collision_pass {
        writeln!(
            handle,
            "[5/7] collisions        OK  0 / {}",
            audit.batch_size
        )?;
    } else {
        writeln!(
            handle,
            "[5/7] collisions        FAIL  {} duplicates detected",
            audit.duplicates
        )?;
    }
    writeln!(
        handle,
        "[6/7] entropy           OK  {:.2} bits (NIST: memorized={} high-value={} crypto-equiv={})",
        audit.entropy.total_entropy,
        if audit.nist_memorized { "OK" } else { "no" },
        if audit.nist_high_value { "OK" } else { "no" },
        if audit.nist_crypto_equiv { "OK" } else { "no" },
    )?;
    if audit.selected_frameworks_pass {
        writeln!(
            handle,
            "[7/7] compliance        OK  selected framework requirements passed"
        )?;
    } else {
        writeln!(
            handle,
            "[7/7] compliance        FAIL  one or more selected frameworks failed"
        )?;
    }

    let format_selected_frameworks = |password: &paranoid_core::GeneratedPassword| {
        let selected = password
            .compliance
            .iter()
            .filter(|status| status.selected)
            .map(|status| format!("{}={}", status.id, if status.passed { "OK" } else { "no" }))
            .collect::<Vec<_>>()
            .join(", ");
        if selected.is_empty() {
            "none".to_string()
        } else {
            selected
        }
    };

    if let Some(primary) = report.passwords.first() {
        let selected = format_selected_frameworks(primary);
        writeln!(
            handle,
            "primary: {}  sha256={}  patterns={}  selected-frameworks={}  pass={}",
            secure_preview(primary.value.as_str()),
            primary.sha256_hex,
            primary.pattern_issues,
            selected,
            if primary.all_pass { "yes" } else { "no" }
        )?;
    }
    if report.passwords.len() > 1 {
        for (index, password) in report.passwords.iter().enumerate().skip(1) {
            let selected = format_selected_frameworks(password);
            writeln!(
                handle,
                "additional[{}]: {}  patterns={}  selected-frameworks={}  pass={}",
                index + 1,
                secure_preview(password.value.as_str()),
                password.pattern_issues,
                selected,
                if password.all_pass { "yes" } else { "no" }
            )?;
        }
    }
    writeln!(
        handle,
        "generator:       batch_stats={} per_password={} selected_frameworks={}",
        if audit.chi2_pass && audit.serial_pass && audit.collision_pass {
            "pass"
        } else {
            "review"
        },
        if audit.passwords_all_pass {
            "pass"
        } else {
            "review"
        },
        if audit.selected_frameworks_pass {
            "pass"
        } else {
            "review"
        }
    )?;
    writeln!(
        handle,
        "audit: {}",
        if audit.overall_pass { "PASS" } else { "FAIL" }
    )?;
    Ok(())
}

fn map_error_to_exit_code(error: &ParanoidError) -> i32 {
    match error {
        ParanoidError::InvalidArguments(_) | ParanoidError::ImpossibleRequirements(_) => EX_USAGE,
        ParanoidError::RandomFailure(_) => EX_CSPRNG,
        ParanoidError::HashFailure(_) => EX_INTERNAL,
        ParanoidError::ExhaustedAttempts => EX_CONSTRAINTS,
        ParanoidError::CertificateFailure(_) => EX_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_preview_masks_multi_byte_passwords_without_panicking() {
        assert_eq!(secure_preview("密码123"), "•码123");
        assert_eq!(secure_preview("パスワード7890"), "•••••7890");
    }

    #[test]
    fn auto_mode_launches_tui_on_interactive_terminal_without_operational_flags() {
        let options = CliOptions::default();
        assert!(should_launch_tui(&options, true));
    }

    #[test]
    fn auto_mode_stays_headless_when_operational_flags_are_present() {
        let options = CliOptions {
            explicit_operational_flag: true,
            ..CliOptions::default()
        };
        assert!(!should_launch_tui(&options, true));
    }

    #[test]
    fn auto_mode_stays_headless_when_not_interactive() {
        let options = CliOptions::default();
        assert!(!should_launch_tui(&options, false));
    }

    #[test]
    fn explicit_modes_override_auto_detection() {
        let tui = CliOptions {
            mode: LaunchMode::Tui,
            explicit_operational_flag: true,
            ..CliOptions::default()
        };
        let cli = CliOptions {
            mode: LaunchMode::Cli,
            ..CliOptions::default()
        };

        assert!(should_launch_tui(&tui, false));
        assert!(!should_launch_tui(&cli, true));
    }

    #[test]
    fn json_flag_forces_headless_structured_output() {
        let ParseOutcome::Run(options) = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--json"),
        ])
        .expect("parse") else {
            panic!("expected run options");
        };

        assert_eq!(options.output, OutputFormat::Json);
        assert!(options.explicit_operational_flag);
        assert!(!should_launch_tui(&options, true));
    }

    #[test]
    fn audit_jsonl_and_profile_flags_are_policy_inputs() {
        let ParseOutcome::Run(options) = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--profile"),
            OsString::from("federal-ready"),
            OsString::from("--audit-jsonl"),
            OsString::from("audit.jsonl"),
        ])
        .expect("parse") else {
            panic!("expected run options");
        };

        assert_eq!(options.profile, OpsProfile::FederalReady);
        assert_eq!(options.audit_jsonl, Some(PathBuf::from("audit.jsonl")));
        assert!(options.explicit_operational_flag);
    }

    #[test]
    fn federal_evidence_forces_federal_json_mode() {
        let ParseOutcome::Run(options) = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--federal-evidence"),
        ])
        .expect("parse") else {
            panic!("expected run options");
        };

        assert!(options.federal_evidence);
        assert_eq!(options.profile, OpsProfile::FederalReady);
        assert_eq!(options.output, OutputFormat::Json);
        assert!(options.require_audit_sink);
        assert!(!should_launch_tui(&options, true));
    }

    #[test]
    fn evidence_flag_is_the_documented_federal_evidence_alias() {
        // brand.md §3c/§4: `--evidence` is the user-facing spelling for the
        // "Evidence bundle" action; it must behave identically to
        // `--federal-evidence`.
        let ParseOutcome::Run(options) = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--evidence"),
        ])
        .expect("parse") else {
            panic!("expected run options");
        };

        assert!(options.federal_evidence);
        assert_eq!(options.profile, OpsProfile::FederalReady);
        assert_eq!(options.output, OutputFormat::Json);
        assert!(options.require_audit_sink);
    }

    #[test]
    fn assurance_strict_is_the_documented_federal_ready_alias() {
        // brand.md §3c: `--assurance strict` is the user-facing spelling
        // for the `federal-ready` profile ("apply the strictest audit and
        // evidence rules").
        let ParseOutcome::Run(options) = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--assurance"),
            OsString::from("strict"),
        ])
        .expect("parse") else {
            panic!("expected run options");
        };

        assert_eq!(options.profile, OpsProfile::FederalReady);
        assert!(options.require_audit_sink);
        assert!(options.explicit_operational_flag);
    }

    #[test]
    fn assurance_rejects_unknown_levels() {
        let result = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--assurance"),
            OsString::from("loose"),
        ]);

        match result {
            Ok(_) => panic!("unknown assurance level must be rejected"),
            Err(error) => assert!(error.to_string().contains("strict")),
        }
    }

    #[test]
    fn detect_environment_forces_json_mode() {
        let ParseOutcome::Run(options) = parse_args(vec![
            OsString::from("paranoid-passwd"),
            OsString::from("--detect-environment"),
        ])
        .expect("parse") else {
            panic!("expected run options");
        };

        assert!(options.detect_environment);
        assert_eq!(options.output, OutputFormat::Json);
        assert!(options.explicit_operational_flag);
        assert!(!should_launch_tui(&options, true));
    }
}
