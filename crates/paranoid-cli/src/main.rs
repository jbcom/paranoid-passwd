mod tui;
mod vault_cli;

use lexopt::prelude::*;
use paranoid_core::{
    CharsetSpec, FrameworkId, GenerationReport, ParanoidError, ParanoidRequest, VERSION,
    execute_request,
};
use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
};

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 1;
const EX_CSPRNG: i32 = 2;
const EX_AUDIT_FAIL: i32 = 3;
const EX_INTERNAL: i32 = 4;
const EX_CONSTRAINTS: i32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    Auto,
    Cli,
    Tui,
}

#[derive(Debug, Clone)]
struct CliOptions {
    request: ParanoidRequest,
    audit: bool,
    quiet: bool,
    mode: LaunchMode,
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
            explicit_operational_flag: false,
        }
    }
}

fn main() {
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
        return vault_cli::run(&raw_args[2..]);
    }

    let options = match parse_args(raw_args)? {
        ParseOutcome::Run(options) => options,
        ParseOutcome::Exit(code) => return Ok(code),
    };
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    let launch_tui = matches!(options.mode, LaunchMode::Tui)
        || (matches!(options.mode, LaunchMode::Auto)
            && interactive
            && !options.explicit_operational_flag);

    if launch_tui {
        return tui::run().map(|_| EX_OK);
    }

    let report = match execute_request(&options.request, options.audit, |_| {}) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(map_error_to_exit_code(&error));
        }
    };

    print_passwords(&report)?;
    if options.audit {
        if !options.quiet {
            print_audit(&report)?;
        }
        if report
            .audit
            .as_ref()
            .is_some_and(|audit| !audit.overall_pass)
        {
            return Ok(EX_AUDIT_FAIL);
        }
    } else if !options.quiet {
        eprintln!("audit: skipped");
    }

    Ok(EX_OK)
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

fn print_usage(mut out: impl Write) -> io::Result<()> {
    writeln!(
        out,
        "\
Usage: paranoid-passwd [OPTIONS]
       paranoid-passwd vault [OPTIONS] <SUBCOMMAND>

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
      --no-audit           Skip the statistical audit
      --quiet              Suppress audit stage output on stderr
  -V, --version            Print version info and exit
  -h, --help               Print this help and exit

Vault:
  vault                    Manage the local encrypted vault

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

    if let Some(primary) = report.passwords.first() {
        writeln!(
            handle,
            "primary: {}  sha256={}  patterns={}",
            secure_preview(primary.value.as_str()),
            primary.sha256_hex,
            primary.pattern_issues
        )?;
    }
    if report.passwords.len() > 1 {
        for (index, password) in report.passwords.iter().enumerate().skip(1) {
            writeln!(
                handle,
                "additional[{}]: {}  patterns={}  pass={}",
                index + 1,
                secure_preview(password.value.as_str()),
                password.pattern_issues,
                if password.all_pass { "yes" } else { "no" }
            )?;
        }
    }
    if !report.request.selected_frameworks.is_empty() {
        let selected = report
            .passwords
            .first()
            .map(|password| {
                password
                    .compliance
                    .iter()
                    .filter(|status| status.selected)
                    .map(|status| {
                        format!("{}={}", status.id, if status.passed { "OK" } else { "no" })
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        writeln!(handle, "compliance:      {selected}")?;
    }
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
    }
}

fn secure_preview(password: &str) -> String {
    if password.len() <= 4 {
        return password.to_string();
    }
    let suffix = &password[password.len() - 4..];
    format!("{}{}", "•".repeat(password.len() - 4), suffix)
}
