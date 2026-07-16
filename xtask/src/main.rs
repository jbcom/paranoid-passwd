use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde_json::Value;

const EXCLUDED_PREFIXES: &[&str] = &[
    ".git/",
    ".tox/",
    "dist/",
    "docs/_build/",
    "docs/api/crates/",
    "node_modules/",
    "target/",
    "vendor/",
];

const RECOMMENDED_EXTERNAL_TOOLS: &[&str] = &[
    "shellcheck",
    "codeql",
    "semgrep",
    "cargo-deny",
    "cargo-audit",
    "cargo-vet",
    "syft",
    "trivy",
    "osv-scanner",
];

const BUILDER_OWNED_SCANNER_TOOLS: &[&str] =
    &["cargo-audit", "semgrep", "osv-scanner", "syft", "trivy"];

const SCANNER_TOOLCHAIN_MANIFEST: &str = "supply-chain/scanner-toolchain.env";

/// Advisories that are actionable per osv-scanner (a fixed version exists upstream) but are
/// pinned behind a transitive dependency's own manifest constraint that this workspace cannot
/// loosen with `cargo update`. Each entry documents why the advisory cannot currently be
/// resolved and the exact upstream condition that would let it be dropped from this list.
/// Allowed findings are never silently swallowed: `check_osv_actionable_findings` still prints
/// them as `WARN` lines so they stay visible in scan output.
const ALLOWED_OSV_ADVISORIES: &[AllowedOsvAdvisory] = &[
    AllowedOsvAdvisory {
        crate_name: "quick-xml",
        advisory_id: "RUSTSEC-2026-0194",
        reason: "quick-xml is pinned to \"^0.39\" by wayland-scanner v0.31.10's own Cargo.toml \
                 (the latest wayland-scanner published on crates.io), reached transitively via \
                 paranoid-gui -> slint 1.16.1 -> i-slint-backend-winit -> softbuffer -> \
                 wayland-client -> wayland-scanner. In this position quick-xml only parses the \
                 repo-local Wayland protocol XML files bundled with wayland-scanner at build \
                 time for code generation; it never parses attacker-controlled or \
                 network-sourced input, so the quadratic-parsing DoS this advisory describes is \
                 not reachable here.",
        revisit_condition: "drop this entry once a wayland-scanner release raises its quick-xml \
                             requirement to >= 0.41.0 and `cargo update -p quick-xml` can reach \
                             the fixed version",
    },
    AllowedOsvAdvisory {
        crate_name: "quick-xml",
        advisory_id: "RUSTSEC-2026-0195",
        reason: "Same pin as RUSTSEC-2026-0194: quick-xml is held at \"^0.39\" by \
                 wayland-scanner v0.31.10's own Cargo.toml, reached transitively via \
                 paranoid-gui -> slint 1.16.1 -> i-slint-backend-winit -> softbuffer -> \
                 wayland-client -> wayland-scanner. quick-xml only parses the repo-local \
                 Wayland protocol XML bundled with wayland-scanner at build time, never \
                 attacker-controlled input, so the unbounded namespace-declaration allocation \
                 this advisory describes is not reachable here.",
        revisit_condition: "drop this entry once a wayland-scanner release raises its quick-xml \
                             requirement to >= 0.41.0 and `cargo update -p quick-xml` can reach \
                             the fixed version",
    },
];

const HOST_LOCAL_SCANNER_VERSION_CHECKS: &[HostLocalScannerVersionCheck] = &[
    HostLocalScannerVersionCheck {
        tool: "shellcheck",
        manifest_key: "HOST_SHELLCHECK_VERSION",
        command: "shellcheck",
        args: &["--version"],
    },
    HostLocalScannerVersionCheck {
        tool: "cargo-deny",
        manifest_key: "HOST_CARGO_DENY_VERSION",
        command: "cargo-deny",
        args: &["--version"],
    },
    HostLocalScannerVersionCheck {
        tool: "cargo-audit",
        manifest_key: "HOST_CARGO_AUDIT_VERSION",
        command: "cargo-audit",
        args: &["--version"],
    },
    HostLocalScannerVersionCheck {
        tool: "cargo-vet",
        manifest_key: "HOST_CARGO_VET_VERSION",
        command: "cargo-vet",
        args: &["--version"],
    },
    HostLocalScannerVersionCheck {
        tool: "codeql",
        manifest_key: "HOST_CODEQL_CLI_VERSION",
        command: "codeql",
        args: &["version"],
    },
];

#[derive(Debug)]
struct Finding {
    check: &'static str,
    message: String,
}

#[derive(Debug)]
struct SecretPattern {
    name: &'static str,
    pattern: Regex,
}

#[derive(Debug)]
struct HostLocalScannerVersionCheck {
    tool: &'static str,
    manifest_key: &'static str,
    command: &'static str,
    args: &'static [&'static str],
}

#[derive(Debug)]
struct AllowedOsvAdvisory {
    crate_name: &'static str,
    advisory_id: &'static str,
    reason: &'static str,
    revisit_condition: &'static str,
}

fn allowed_osv_advisory(
    crate_name: &str,
    advisory_id: &str,
) -> Option<&'static AllowedOsvAdvisory> {
    ALLOWED_OSV_ADVISORIES
        .iter()
        .find(|entry| entry.crate_name == crate_name && entry.advisory_id == advisory_id)
}

fn main() -> Result<()> {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_string());
    match command.as_str() {
        "verify-deep" => verify_deep(),
        "dependency-scan" => dependency_scan(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => bail!("unknown xtask command {unknown:?}"),
    }
}

fn print_help() {
    println!("Usage: cargo run -p xtask -- verify-deep");
    println!("       cargo run -p xtask -- dependency-scan");
}

fn verify_deep() -> Result<()> {
    println!("Local Deep Quality Gate");
    println!();

    let repo_root = repo_root()?;
    let files = tracked_files(&repo_root)?;
    let mut findings = Vec::new();

    findings.extend(check_toolchain_policy(&repo_root)?);
    findings.extend(check_cargo_metadata(&repo_root)?);
    findings.extend(check_shell_scripts(&repo_root, &files)?);
    findings.extend(check_python_syntax(&repo_root, &files)?);
    findings.extend(check_secret_scan(&repo_root, &files)?);
    findings.extend(check_external_tool_visibility()?);
    findings.extend(check_host_local_scanner_versions(&repo_root)?);
    findings.extend(check_local_security_scanners(&repo_root)?);

    println!();
    if findings.is_empty() {
        println!("PASS local quality gate");
        return Ok(());
    }

    println!("FAIL local quality gate");
    for finding in findings {
        println!("- [{}] {}", finding.check, finding.message);
    }
    bail!("local quality gate failed")
}

fn dependency_scan() -> Result<()> {
    println!("PR Dependency Scan");
    println!();

    let repo_root = repo_root()?;
    let mut findings = Vec::new();

    print_step("Running cargo-audit");
    let status = Command::new("cargo")
        .args(["audit", "--no-fetch", "--stale"])
        .current_dir(&repo_root)
        .status()
        .context("failed to run cargo-audit")?;
    if !status.success() {
        findings.push(Finding::new(
            "cargo-audit",
            format!(
                "cargo-audit failed with exit code {}",
                status.code().unwrap_or(-1)
            ),
        ));
    }

    print_step("Running osv-scanner");
    findings.extend(check_osv_actionable_findings(&repo_root)?);

    println!();
    if findings.is_empty() {
        println!("PASS dependency scan");
        return Ok(());
    }

    println!("FAIL dependency scan");
    for finding in findings {
        println!("- [{}] {}", finding.check, finding.message);
    }
    bail!("dependency scan failed")
}

fn repo_root() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to locate git repository root")?;
    if !output.status.success() {
        bail!("git rev-parse --show-toplevel failed");
    }
    let root = String::from_utf8(output.stdout).context("git root was not valid UTF-8")?;
    Ok(PathBuf::from(root.trim()))
}

fn tracked_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to list tracked files")?;
    if !output.status.success() {
        bail!("git ls-files failed");
    }

    let mut files = Vec::new();
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8(raw.to_vec()).context("tracked path was not valid UTF-8")?;
        let path = PathBuf::from(path);
        if !is_excluded(&path) {
            files.push(path);
        }
    }
    Ok(files)
}

fn is_excluded(path: &Path) -> bool {
    let normalized = path.to_string_lossy();
    EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| normalized == prefix.trim_end_matches('/') || normalized.starts_with(prefix))
}

fn print_step(message: &str) {
    println!("==> {message}");
}

fn check_toolchain_policy(repo_root: &Path) -> Result<Vec<Finding>> {
    print_step("Checking Rust toolchain policy");
    let cargo_toml = fs::read_to_string(repo_root.join("Cargo.toml")).context("read Cargo.toml")?;
    let toolchain_toml = fs::read_to_string(repo_root.join("rust-toolchain.toml"))
        .context("read rust-toolchain.toml")?;
    let mut findings = Vec::new();

    if !cargo_toml.contains("edition = \"2024\"") {
        findings.push(Finding::new(
            "toolchain",
            "workspace must stay on Rust edition 2024",
        ));
    }
    if !cargo_toml.contains("rust-version = \"1.95\"") {
        findings.push(Finding::new(
            "toolchain",
            "workspace rust-version must stay pinned to 1.95",
        ));
    }
    if !toolchain_toml.contains("channel = \"1.95.0\"") {
        findings.push(Finding::new(
            "toolchain",
            "rust-toolchain.toml must stay pinned to Rust 1.95.0",
        ));
    }
    if !toolchain_toml.contains("\"clippy\"") || !toolchain_toml.contains("\"rustfmt\"") {
        findings.push(Finding::new(
            "toolchain",
            "rust-toolchain.toml must include clippy and rustfmt",
        ));
    }

    Ok(findings)
}

fn check_cargo_metadata(repo_root: &Path) -> Result<Vec<Finding>> {
    print_step("Checking locked offline Cargo metadata");
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--frozen",
            "--offline",
            "--format-version",
            "1",
        ])
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to run cargo metadata")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(vec![Finding::new(
            "cargo-metadata",
            format!("offline Cargo metadata failed: {}", stderr.trim()),
        )]);
    }

    let metadata: Value = serde_json::from_slice(&output.stdout).context("parse cargo metadata")?;
    let workspace_members = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("cargo metadata missing workspace_members"))?;
    let workspace_members: Vec<&str> = workspace_members.iter().filter_map(Value::as_str).collect();
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("cargo metadata missing packages"))?;

    let mut findings = Vec::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let package_id = package
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let source = package.get("source").and_then(Value::as_str);
        let license_expr = package.get("license").and_then(Value::as_str);

        if let Some(source) = source {
            if !source.starts_with("registry+") {
                findings.push(Finding::new(
                    "cargo-source",
                    format!("{name} resolves from non-registry source {source:?}"),
                ));
            }
            if source.starts_with("git+") {
                findings.push(Finding::new(
                    "cargo-source",
                    format!("{name} resolves from a git dependency"),
                ));
            }
        }

        if license_expr.is_none() {
            findings.push(Finding::new(
                "cargo-license",
                format!("{name} is missing a Cargo license expression"),
            ));
        }

        if workspace_members.contains(&package_id) && license_expr != Some("GPL-3.0-only") {
            findings.push(Finding::new(
                "workspace-license",
                format!("{name} must remain GPL-3.0-only, found {license_expr:?}"),
            ));
        }
    }

    Ok(findings)
}

fn check_shell_scripts(repo_root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let shell_files: Vec<PathBuf> = files
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "sh"))
        .cloned()
        .collect();
    if shell_files.is_empty() {
        return Ok(Vec::new());
    }

    print_step("Running ShellCheck on repo-owned shell scripts");
    let Some(shellcheck) = find_in_path("shellcheck") else {
        if builder_scanner_subset_enabled() {
            println!(
                "WARN shellcheck is not available in the Wolfi builder package set; running bash syntax checks instead"
            );
            return check_shell_script_syntax(repo_root, &shell_files);
        }
        return Ok(vec![Finding::new(
            "shellcheck",
            "shellcheck is required for make verify-deep",
        )]);
    };

    let mut command = Command::new(shellcheck);
    command
        .arg("--severity=warning")
        .args(shell_files)
        .current_dir(repo_root);
    let status = command.status().context("failed to run shellcheck")?;
    if status.success() {
        Ok(Vec::new())
    } else {
        Ok(vec![Finding::new(
            "shellcheck",
            "ShellCheck reported warning-or-higher findings",
        )])
    }
}

fn check_shell_script_syntax(repo_root: &Path, shell_files: &[PathBuf]) -> Result<Vec<Finding>> {
    print_step("Parsing repo-owned shell scripts with bash -n");
    let Some(bash) = find_in_path("bash") else {
        return Ok(vec![Finding::new(
            "shell-syntax",
            "bash is required for builder-emulated shell syntax checks",
        )]);
    };

    let mut findings = Vec::new();
    for shell_file in shell_files {
        let status = Command::new(&bash)
            .arg("-n")
            .arg(shell_file)
            .current_dir(repo_root)
            .status()
            .with_context(|| format!("failed to parse {}", shell_file.display()))?;
        if !status.success() {
            findings.push(Finding::new(
                "shell-syntax",
                format!("{} failed bash -n", shell_file.display()),
            ));
        }
    }
    Ok(findings)
}

fn check_python_syntax(repo_root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let python_files: Vec<PathBuf> = files
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "py"))
        .cloned()
        .collect();
    if python_files.is_empty() {
        return Ok(Vec::new());
    }

    print_step("Parsing repo-owned Python scripts");
    let python = find_in_path("python3").unwrap_or_else(|| PathBuf::from("python3"));
    let syntax_check = r#"
import ast
import pathlib
import sys

failed = False
for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    try:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        print(f"{path}:{exc.lineno}:{exc.offset}: {exc.msg}", file=sys.stderr)
        failed = True

raise SystemExit(1 if failed else 0)
"#;
    let status = Command::new(python)
        .arg("-c")
        .arg(syntax_check)
        .args(python_files)
        .current_dir(repo_root)
        .status()
        .context("failed to run Python syntax parser")?;
    if status.success() {
        Ok(Vec::new())
    } else {
        Ok(vec![Finding::new(
            "python-syntax",
            "Python syntax parsing failed",
        )])
    }
}

fn check_secret_scan(repo_root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    print_step("Scanning tracked repo-owned files for committed secrets");
    let patterns = secret_patterns()?;
    let generic_secret_literal = Regex::new(
        r#"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|signing[_-]?key)\b\s*[:=]\s*["'][^"']{16,}["']"#,
    )
    .context("compile generic secret regex")?;

    let mut findings = Vec::new();
    for path in files {
        if !is_text_file(repo_root, path)? {
            continue;
        }
        let full_path = repo_root.join(path);
        let Ok(content) = fs::read_to_string(&full_path) else {
            continue;
        };
        for (line_index, line) in content.lines().enumerate() {
            let line_number = line_index + 1;
            for pattern in &patterns {
                if pattern.pattern.is_match(line) {
                    findings.push(Finding::new(
                        "secret-scan",
                        format!("{}:{line_number}: matched {}", path.display(), pattern.name),
                    ));
                }
            }
            if is_config_file(path) && generic_secret_literal.is_match(line) {
                findings.push(Finding::new(
                    "secret-scan",
                    format!(
                        "{}:{line_number}: matched generic secret literal",
                        path.display()
                    ),
                ));
            }
        }
    }
    Ok(findings)
}

fn secret_patterns() -> Result<Vec<SecretPattern>> {
    Ok(vec![
        SecretPattern::new(
            "private-key-block",
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
        )?,
        SecretPattern::new("aws-access-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")?,
        SecretPattern::new("github-token", r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")?,
        SecretPattern::new("openai-api-key", r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{18,}\b")?,
        SecretPattern::new("slack-token", r"\bxox(?:b|p|o|a|r)-[A-Za-z0-9-]{20,}\b")?,
        SecretPattern::new("stripe-secret-key", r"\bsk_live_[A-Za-z0-9]{20,}\b")?,
    ])
}

fn is_config_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("env" | "ini" | "toml" | "yaml" | "yml")
    )
}

fn is_text_file(repo_root: &Path, path: &Path) -> Result<bool> {
    let bytes =
        fs::read(repo_root.join(path)).with_context(|| format!("read {}", path.display()))?;
    Ok(!bytes.iter().take(4096).any(|byte| *byte == 0))
}

fn check_external_tool_visibility() -> Result<Vec<Finding>> {
    print_step("Checking optional local security tool visibility");
    let expected_tools = if builder_scanner_subset_enabled() {
        BUILDER_OWNED_SCANNER_TOOLS
    } else {
        RECOMMENDED_EXTERNAL_TOOLS
    };
    let missing: Vec<&str> = expected_tools
        .iter()
        .copied()
        .filter(|tool| find_in_path(tool).is_none())
        .collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }

    if builder_scanner_subset_enabled() {
        return Ok(vec![Finding::new(
            "builder-scanners",
            format!(
                "missing builder-owned scanner tools: {}; update .github/actions/builder/Dockerfile or supply-chain/scanner-toolchain.env",
                missing.join(", ")
            ),
        )]);
    }

    let message = format!(
        "missing optional local tools: {}; set PARANOID_STRICT_EXTERNAL_TOOLS=1 to make this fatal",
        missing.join(", ")
    );
    println!("WARN {message}");
    if env::var("PARANOID_STRICT_EXTERNAL_TOOLS").as_deref() == Ok("1") {
        Ok(vec![Finding::new("external-tools", message)])
    } else {
        Ok(Vec::new())
    }
}

fn check_host_local_scanner_versions(repo_root: &Path) -> Result<Vec<Finding>> {
    if env::var("PARANOID_STRICT_EXTERNAL_TOOLS").as_deref() != Ok("1") {
        return Ok(Vec::new());
    }

    print_step("Checking manifest-pinned local scanner versions");
    let manifest = load_scanner_manifest(repo_root)?;
    let mut findings = Vec::new();
    for check in HOST_LOCAL_SCANNER_VERSION_CHECKS {
        let Some(expected_version) = manifest.get(check.manifest_key) else {
            findings.push(Finding::new(
                "scanner-version",
                format!(
                    "{} is missing from {SCANNER_TOOLCHAIN_MANIFEST}",
                    check.manifest_key
                ),
            ));
            continue;
        };
        let Some(binary) = find_in_path(check.command) else {
            findings.push(Finding::new(
                "scanner-version",
                format!(
                    "{} is required at version {expected_version} but was not found",
                    check.tool
                ),
            ));
            continue;
        };

        let output = Command::new(&binary)
            .args(check.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("failed to run {} version check", check.tool))?;
        if !output.status.success() {
            findings.push(Finding::new(
                "scanner-version",
                format!(
                    "{} version check failed with exit code {}",
                    check.tool,
                    output.status.code().unwrap_or(-1)
                ),
            ));
            continue;
        }

        let mut version_output = String::from_utf8_lossy(&output.stdout).into_owned();
        version_output.push_str(&String::from_utf8_lossy(&output.stderr));
        if !version_output.contains(expected_version) {
            findings.push(Finding::new(
                "scanner-version",
                format!(
                    "{} version drifted from {expected_version}: {}",
                    check.tool,
                    version_output
                        .lines()
                        .next()
                        .unwrap_or("<no version output>")
                ),
            ));
        }
    }
    Ok(findings)
}

fn load_scanner_manifest(repo_root: &Path) -> Result<HashMap<String, String>> {
    let manifest_path = repo_root.join(SCANNER_TOOLCHAIN_MANIFEST);
    let content = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    Ok(parse_scanner_manifest(&content))
}

fn parse_scanner_manifest(content: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        values.insert(
            key.trim().to_string(),
            raw_value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string(),
        );
    }
    values
}

fn check_local_security_scanners(repo_root: &Path) -> Result<Vec<Finding>> {
    if env::var("PARANOID_RUN_LOCAL_SCANNERS").as_deref() != Ok("1") {
        return Ok(Vec::new());
    }

    print_step("Running local security scanners");
    let mut commands: Vec<(&str, &str, Vec<&str>)> = vec![
        (
            "cargo-audit",
            "cargo",
            vec!["audit", "--no-fetch", "--stale"],
        ),
        (
            "semgrep",
            "semgrep",
            vec![
                "scan",
                "--config",
                "auto",
                "--error",
                "--exclude",
                "vendor",
                "--exclude",
                "target",
                "--exclude",
                ".tox",
                "--exclude",
                "docs/_build",
                "--exclude",
                "docs/api/crates",
                "--exclude",
                "dist",
                ".",
            ],
        ),
    ];
    if !builder_scanner_subset_enabled() {
        commands.insert(
            1,
            (
                "cargo-deny",
                "cargo",
                vec![
                    "deny",
                    "check",
                    "advisories",
                    "licenses",
                    "sources",
                    "bans",
                    "-A",
                    "unmaintained",
                    "-A",
                    "unsound",
                    "--hide-inclusion-graph",
                ],
            ),
        );
    }

    let mut findings = Vec::new();
    for (check, binary, args) in commands {
        let status = Command::new(binary)
            .args(args)
            .current_dir(repo_root)
            .status()
            .with_context(|| format!("failed to run {check}"))?;
        if !status.success() {
            findings.push(Finding::new(
                check,
                format!(
                    "{check} failed with exit code {}",
                    status.code().unwrap_or(-1)
                ),
            ));
        }
    }
    findings.extend(check_osv_actionable_findings(repo_root)?);
    Ok(findings)
}

fn check_osv_actionable_findings(repo_root: &Path) -> Result<Vec<Finding>> {
    let report_path = repo_root.join("dist/local-osv.json");
    fs::create_dir_all(repo_root.join("dist")).context("create dist for local scanner reports")?;
    let status = Command::new("osv-scanner")
        .args(["scan", "source", "--format", "json", "--output-file"])
        .arg(&report_path)
        .arg(repo_root.join("Cargo.lock"))
        .current_dir(repo_root)
        .status()
        .context("failed to run osv-scanner")?;
    if !status.success() && !report_path.exists() {
        return Ok(vec![Finding::new(
            "osv-scanner",
            format!(
                "osv-scanner failed before writing a report, exit code {}",
                status.code().unwrap_or(-1)
            ),
        )]);
    }

    let report: Value = serde_json::from_slice(
        &fs::read(&report_path).with_context(|| format!("read {}", report_path.display()))?,
    )
    .context("parse osv-scanner report")?;

    let mut findings = Vec::new();
    for package in osv_packages(&report) {
        let name = package
            .get("package")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let version = package
            .get("package")
            .and_then(|value| value.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let Some(vulnerabilities) = package.get("vulnerabilities").and_then(Value::as_array) else {
            continue;
        };
        for vulnerability in vulnerabilities {
            let id = vulnerability
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            if let Some(allowed) = allowed_osv_advisory(name, id) {
                println!(
                    "WARN osv-scanner: {name} {version} has allowed advisory {id} (pinned, not silenced) - {}; revisit: {}",
                    allowed.reason, allowed.revisit_condition
                );
            } else if osv_has_fixed_version(vulnerability) || !osv_is_unmaintained(vulnerability) {
                findings.push(Finding::new(
                    "osv-scanner",
                    format!("{name} {version} has actionable advisory {id}"),
                ));
            } else {
                println!(
                    "WARN osv-scanner: {name} {version} has unmaintained advisory {id} with no fixed version"
                );
            }
        }
    }

    Ok(findings)
}

fn osv_packages(report: &Value) -> Vec<&Value> {
    let mut packages = Vec::new();
    let Some(results) = report.get("results").and_then(Value::as_array) else {
        return packages;
    };
    for result in results {
        if let Some(result_packages) = result.get("packages").and_then(Value::as_array) {
            packages.extend(result_packages);
        }
    }
    packages
}

fn osv_has_fixed_version(vulnerability: &Value) -> bool {
    let Some(affected) = vulnerability.get("affected").and_then(Value::as_array) else {
        return false;
    };
    affected.iter().any(|affected_entry| {
        affected_entry
            .get("ranges")
            .and_then(Value::as_array)
            .is_some_and(|ranges| {
                ranges.iter().any(|range| {
                    range
                        .get("events")
                        .and_then(Value::as_array)
                        .is_some_and(|events| {
                            events
                                .iter()
                                .any(|event| event.get("fixed").and_then(Value::as_str).is_some())
                        })
                })
            })
    })
}

fn osv_is_unmaintained(vulnerability: &Value) -> bool {
    vulnerability
        .get("affected")
        .and_then(Value::as_array)
        .is_some_and(|affected| {
            affected.iter().any(|affected_entry| {
                affected_entry
                    .get("database_specific")
                    .and_then(|value| value.get("informational"))
                    .and_then(Value::as_str)
                    == Some("unmaintained")
            })
        })
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var)
        .map(|path| path.join(binary))
        .find(|candidate| candidate.is_file())
}

fn builder_scanner_subset_enabled() -> bool {
    env::var("PARANOID_BUILDER_SCANNER_SUBSET").as_deref() == Ok("1")
}

impl Finding {
    fn new(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            check,
            message: message.into(),
        }
    }
}

impl SecretPattern {
    fn new(name: &'static str, pattern: &str) -> Result<Self> {
        Ok(Self {
            name,
            pattern: Regex::new(pattern).with_context(|| format!("compile {name} regex"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{allowed_osv_advisory, parse_scanner_manifest};

    #[test]
    fn allowed_osv_advisory_matches_pinned_quick_xml_findings() {
        let rustsec_2026_0194 =
            allowed_osv_advisory("quick-xml", "RUSTSEC-2026-0194").expect("entry must exist");
        assert!(rustsec_2026_0194.reason.contains("wayland-scanner"));
        assert!(
            rustsec_2026_0194
                .revisit_condition
                .contains("quick-xml >= 0.41.0")
                || rustsec_2026_0194.revisit_condition.contains(">= 0.41.0")
        );

        let rustsec_2026_0195 =
            allowed_osv_advisory("quick-xml", "RUSTSEC-2026-0195").expect("entry must exist");
        assert!(rustsec_2026_0195.reason.contains("wayland-scanner"));

        assert!(allowed_osv_advisory("quick-xml", "RUSTSEC-2099-9999").is_none());
        assert!(allowed_osv_advisory("anyhow", "RUSTSEC-2026-0194").is_none());
    }

    #[test]
    fn scanner_manifest_parser_keeps_pinned_tool_versions() {
        let values = parse_scanner_manifest(
            r#"
# comment
HOST_LOCAL_SCANNER_TOOLS="shellcheck cargo-deny cargo-audit cargo-vet codeql"
CARGO_AUDIT_APK_PACKAGE=cargo-audit
CARGO_AUDIT_APK_VERSION=0.22.2-r2
RUSTSEC_ADVISORY_DB_REV=20377f44edabca7c4a765ccdcd05935331b6191f
HOST_SHELLCHECK_VERSION=0.11.0
HOST_CARGO_DENY_VERSION=0.19.4
HOST_CARGO_AUDIT_VERSION=0.22.1
HOST_CARGO_VET_VERSION=0.10.2
HOST_CODEQL_CLI_VERSION='2.25.3'
"#,
        );

        assert_eq!(
            values.get("HOST_LOCAL_SCANNER_TOOLS").map(String::as_str),
            Some("shellcheck cargo-deny cargo-audit cargo-vet codeql")
        );
        assert_eq!(
            values.get("HOST_CODEQL_CLI_VERSION").map(String::as_str),
            Some("2.25.3")
        );
        assert_eq!(
            values.get("HOST_CARGO_AUDIT_VERSION").map(String::as_str),
            Some("0.22.1")
        );
        assert_eq!(
            values.get("CARGO_AUDIT_APK_VERSION").map(String::as_str),
            Some("0.22.2-r2")
        );
        assert_eq!(
            values.get("RUSTSEC_ADVISORY_DB_REV").map(String::as_str),
            Some("20377f44edabca7c4a765ccdcd05935331b6191f")
        );
    }
}
