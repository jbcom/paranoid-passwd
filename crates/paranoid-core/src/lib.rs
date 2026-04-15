use openssl::{rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use statrs::distribution::{ChiSquared, ContinuousCDF};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_PASSWORD_LEN: usize = 256;
pub const MAX_CHARSET_LEN: usize = 128;
pub const MAX_BATCH_SIZE: usize = 2_000;
pub const MAX_MULTI_COUNT: usize = 10;
pub const MAX_CONSTRAINED_ATTEMPTS: usize = 100;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const AMBIGUOUS: &str = "0OIl1|";
const AUDIT_TIER_MEMORIZED: f64 = 30.0;
const AUDIT_TIER_HIGH_VALUE: f64 = 80.0;
const AUDIT_TIER_CRYPTO_EQUIV: f64 = 128.0;
const AUDIT_TIER_POST_QUANTUM: f64 = 256.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStage {
    Generate,
    ChiSquared,
    SerialCorrelation,
    CollisionDetection,
    EntropyProofs,
    PatternDetection,
    ThreatAssessment,
    Complete,
}

impl AuditStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Generate => "Password Generation",
            Self::ChiSquared => "Chi-Squared Uniformity",
            Self::SerialCorrelation => "Serial Correlation",
            Self::CollisionDetection => "Collision Detection",
            Self::EntropyProofs => "Entropy & Uniqueness Proofs",
            Self::PatternDetection => "Pattern Detection",
            Self::ThreatAssessment => "LLM Threat Assessment",
            Self::Complete => "Complete",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharRequirements {
    pub min_lowercase: usize,
    pub min_uppercase: usize,
    pub min_digits: usize,
    pub min_symbols: usize,
}

impl CharRequirements {
    pub fn total(self) -> usize {
        self.min_lowercase + self.min_uppercase + self.min_digits + self.min_symbols
    }

    pub fn max_with(self, other: Self) -> Self {
        Self {
            min_lowercase: self.min_lowercase.max(other.min_lowercase),
            min_uppercase: self.min_uppercase.max(other.min_uppercase),
            min_digits: self.min_digits.max(other.min_digits),
            min_symbols: self.min_symbols.max(other.min_symbols),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharsetOptions {
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
    pub include_space: bool,
    pub exclude_ambiguous: bool,
    pub custom_charset: Option<String>,
}

impl Default for CharsetOptions {
    fn default() -> Self {
        Self {
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            include_space: false,
            exclude_ambiguous: false,
            custom_charset: None,
        }
    }
}

impl CharsetOptions {
    pub fn build(&self) -> Result<String, ParanoidError> {
        if let Some(custom) = &self.custom_charset {
            if !custom.trim().is_empty() {
                return validate_charset(custom);
            }
        }

        let mut charset = String::new();
        if self.include_lowercase {
            charset.push_str(LOWER);
        }
        if self.include_uppercase {
            charset.push_str(UPPER);
        }
        if self.include_digits {
            charset.push_str(DIGITS);
        }
        if self.include_symbols {
            charset.push_str(SYMBOLS);
        }
        if self.include_space && !charset.starts_with(' ') {
            charset.insert(0, ' ');
        }
        if self.exclude_ambiguous {
            charset.retain(|ch| !AMBIGUOUS.contains(ch));
        }

        validate_charset(&charset)
    }

    pub fn apply_frameworks(&mut self, combined: &CombinedFrameworkRequirements) {
        if combined.require_lowercase {
            self.include_lowercase = true;
        }
        if combined.require_uppercase {
            self.include_uppercase = true;
        }
        if combined.require_digits {
            self.include_digits = true;
        }
        if combined.require_symbols {
            self.include_symbols = true;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CharsetSpec {
    NamedOrLiteral(String),
    Options(CharsetOptions),
}

impl Default for CharsetSpec {
    fn default() -> Self {
        Self::NamedOrLiteral("full".to_string())
    }
}

impl CharsetSpec {
    pub fn resolve(
        &self,
        combined: &CombinedFrameworkRequirements,
    ) -> Result<String, ParanoidError> {
        match self {
            Self::NamedOrLiteral(spec) => resolve_charset(spec),
            Self::Options(options) => {
                let mut adjusted = options.clone();
                adjusted.apply_frameworks(combined);
                adjusted.build()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum FrameworkId {
    Nist,
    PciDss,
    Hipaa,
    Soc2,
    Gdpr,
    Iso27001,
}

impl FrameworkId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nist => "nist",
            Self::PciDss => "pci_dss",
            Self::Hipaa => "hipaa",
            Self::Soc2 => "soc2",
            Self::Gdpr => "gdpr",
            Self::Iso27001 => "iso27001",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "nist" => Some(Self::Nist),
            "pci" | "pci_dss" | "pci-dss" => Some(Self::PciDss),
            "hipaa" => Some(Self::Hipaa),
            "soc2" | "soc_2" | "soc-2" => Some(Self::Soc2),
            "gdpr" => Some(Self::Gdpr),
            "iso27001" | "iso-27001" | "iso_27001" => Some(Self::Iso27001),
            _ => None,
        }
    }
}

impl fmt::Display for FrameworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ComplianceFramework {
    pub id: FrameworkId,
    pub name: &'static str,
    pub description: &'static str,
    pub min_length: usize,
    pub min_entropy_bits: f64,
    pub require_mixed_case: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
}

pub const FRAMEWORKS: [ComplianceFramework; 6] = [
    ComplianceFramework {
        id: FrameworkId::Nist,
        name: "NIST SP 800-63B",
        description: "US federal digital identity guidance",
        min_length: 8,
        min_entropy_bits: 30.0,
        require_mixed_case: false,
        require_digits: false,
        require_symbols: false,
    },
    ComplianceFramework {
        id: FrameworkId::PciDss,
        name: "PCI DSS 4.0",
        description: "Payment card industry security standard",
        min_length: 12,
        min_entropy_bits: 60.0,
        require_mixed_case: true,
        require_digits: true,
        require_symbols: false,
    },
    ComplianceFramework {
        id: FrameworkId::Hipaa,
        name: "HIPAA",
        description: "US healthcare security guidance",
        min_length: 8,
        min_entropy_bits: 50.0,
        require_mixed_case: true,
        require_digits: true,
        require_symbols: true,
    },
    ComplianceFramework {
        id: FrameworkId::Soc2,
        name: "SOC 2",
        description: "Trust services criteria for SaaS platforms",
        min_length: 8,
        min_entropy_bits: 50.0,
        require_mixed_case: true,
        require_digits: true,
        require_symbols: false,
    },
    ComplianceFramework {
        id: FrameworkId::Gdpr,
        name: "GDPR / ENISA",
        description: "EU data protection implementation guidance",
        min_length: 10,
        min_entropy_bits: 80.0,
        require_mixed_case: true,
        require_digits: true,
        require_symbols: true,
    },
    ComplianceFramework {
        id: FrameworkId::Iso27001,
        name: "ISO 27001",
        description: "International security management controls",
        min_length: 12,
        min_entropy_bits: 90.0,
        require_mixed_case: true,
        require_digits: true,
        require_symbols: true,
    },
];

pub fn frameworks() -> &'static [ComplianceFramework] {
    &FRAMEWORKS
}

pub fn framework_by_id(id: FrameworkId) -> &'static ComplianceFramework {
    FRAMEWORKS
        .iter()
        .find(|framework| framework.id == id)
        .expect("framework ids are static and exhaustive")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CombinedFrameworkRequirements {
    pub min_length: usize,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digits: bool,
    pub require_symbols: bool,
}

pub fn combined_framework_requirements(selected: &[FrameworkId]) -> CombinedFrameworkRequirements {
    let mut combined = CombinedFrameworkRequirements::default();
    for framework_id in selected {
        let framework = framework_by_id(*framework_id);
        combined.min_length = combined.min_length.max(framework.min_length);
        if framework.require_mixed_case {
            combined.require_lowercase = true;
            combined.require_uppercase = true;
        }
        if framework.require_digits {
            combined.require_digits = true;
        }
        if framework.require_symbols {
            combined.require_symbols = true;
        }
    }
    combined
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParanoidRequest {
    pub length: usize,
    pub count: usize,
    pub batch_size: usize,
    pub charset: CharsetSpec,
    pub requirements: CharRequirements,
    pub selected_frameworks: Vec<FrameworkId>,
}

impl Default for ParanoidRequest {
    fn default() -> Self {
        Self {
            length: 32,
            count: 1,
            batch_size: 500,
            charset: CharsetSpec::default(),
            requirements: CharRequirements::default(),
            selected_frameworks: Vec::new(),
        }
    }
}

impl ParanoidRequest {
    pub fn resolve(&self) -> Result<ResolvedRequest, ParanoidError> {
        if self.length == 0 || self.length > MAX_PASSWORD_LEN {
            return Err(ParanoidError::InvalidArguments(format!(
                "--length must be 1..{MAX_PASSWORD_LEN}"
            )));
        }
        if self.count == 0 || self.count > MAX_MULTI_COUNT {
            return Err(ParanoidError::InvalidArguments(format!(
                "--count must be 1..{MAX_MULTI_COUNT}"
            )));
        }
        if self.batch_size == 0 || self.batch_size > MAX_BATCH_SIZE {
            return Err(ParanoidError::InvalidArguments(format!(
                "--batch-size must be 1..{MAX_BATCH_SIZE}"
            )));
        }

        let combined = combined_framework_requirements(&self.selected_frameworks);
        let effective_length = self.length.max(combined.min_length);
        let charset = self.charset.resolve(&combined)?;

        let framework_requirements = CharRequirements {
            min_lowercase: usize::from(combined.require_lowercase),
            min_uppercase: usize::from(combined.require_uppercase),
            min_digits: usize::from(combined.require_digits),
            min_symbols: usize::from(combined.require_symbols),
        };
        let requirements = self.requirements.max_with(framework_requirements);
        ensure_requirements_possible(&charset, effective_length, requirements)?;

        Ok(ResolvedRequest {
            length: effective_length,
            count: self.count,
            batch_size: self.batch_size,
            charset,
            requirements,
            selected_frameworks: self.selected_frameworks.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRequest {
    pub length: usize,
    pub count: usize,
    pub batch_size: usize,
    pub charset: String,
    pub requirements: CharRequirements,
    pub selected_frameworks: Vec<FrameworkId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharacterCounts {
    pub lowercase: usize,
    pub uppercase: usize,
    pub digits: usize,
    pub symbols: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub id: FrameworkId,
    pub name: String,
    pub selected: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EntropyMetrics {
    pub bits_per_char: f64,
    pub total_entropy: f64,
    pub log10_search_space: f64,
    pub brute_force_years: f64,
    pub collision_probability: f64,
    pub passwords_for_50pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPassword {
    pub value: String,
    pub sha256_hex: String,
    pub character_counts: CharacterCounts,
    pub pattern_issues: usize,
    pub compliance: Vec<ComplianceStatus>,
    pub selected_compliance_pass: bool,
    pub all_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub password_length: usize,
    pub charset_size: usize,
    pub chi2_statistic: f64,
    pub chi2_df: usize,
    pub chi2_p_value: f64,
    pub chi2_pass: bool,
    pub serial_correlation: f64,
    pub serial_pass: bool,
    pub batch_size: usize,
    pub duplicates: usize,
    pub collision_pass: bool,
    pub entropy: EntropyMetrics,
    pub nist_memorized: bool,
    pub nist_high_value: bool,
    pub nist_crypto_equiv: bool,
    pub nist_post_quantum: bool,
    pub rejection_max_valid: usize,
    pub rejection_rate_pct: f64,
    pub passwords_all_pass: bool,
    pub selected_frameworks_pass: bool,
    pub overall_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationReport {
    pub request: ResolvedRequest,
    pub passwords: Vec<GeneratedPassword>,
    pub audit: Option<AuditSummary>,
}

#[derive(Debug, Error)]
pub enum ParanoidError {
    #[error("{0}")]
    InvalidArguments(String),
    #[error("{0}")]
    ImpossibleRequirements(String),
    #[error("openssl random failure: {0}")]
    RandomFailure(String),
    #[error("openssl hash failure: {0}")]
    HashFailure(String),
    #[error("constrained generation exhausted attempts")]
    ExhaustedAttempts,
}

pub fn validate_charset(input: &str) -> Result<String, ParanoidError> {
    if input.is_empty() {
        return Err(ParanoidError::InvalidArguments(
            "charset must not be empty".to_string(),
        ));
    }

    let mut seen = [false; 128];
    for byte in input.bytes() {
        if !(32..=126).contains(&byte) {
            return Err(ParanoidError::InvalidArguments(
                "charset must contain printable ASCII only".to_string(),
            ));
        }
        seen[usize::from(byte)] = true;
    }

    let mut normalized = String::new();
    for (idx, included) in seen.iter().enumerate().skip(32).take(95) {
        if *included {
            normalized.push(char::from_u32(idx as u32).expect("ASCII char"));
        }
    }

    if normalized.is_empty() {
        return Err(ParanoidError::InvalidArguments(
            "charset must contain at least one printable character".to_string(),
        ));
    }
    if normalized.len() > MAX_CHARSET_LEN {
        return Err(ParanoidError::InvalidArguments(format!(
            "charset must be <= {MAX_CHARSET_LEN} unique characters"
        )));
    }

    Ok(normalized)
}

pub fn resolve_charset(spec: &str) -> Result<String, ParanoidError> {
    match spec {
        "alnum" => Ok(format!("{DIGITS}{UPPER}{LOWER}")),
        "alnum-symbols" => Ok(format!("{DIGITS}{UPPER}{LOWER}!@#$%^&*-_=+[]{{}};:,.?/")),
        "hex" => Ok("0123456789abcdef".to_string()),
        "full" => {
            let full: String = (33_u8..=126_u8).map(char::from).collect();
            Ok(full)
        }
        literal => validate_charset(literal),
    }
}

fn ensure_requirements_possible(
    charset: &str,
    length: usize,
    requirements: CharRequirements,
) -> Result<(), ParanoidError> {
    if requirements.total() > length {
        return Err(ParanoidError::ImpossibleRequirements(format!(
            "requirements need {} characters total but password length is only {length}",
            requirements.total()
        )));
    }

    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digits = false;
    let mut has_symbols = false;
    for byte in charset.bytes() {
        if byte.is_ascii_lowercase() {
            has_lowercase = true;
        } else if byte.is_ascii_uppercase() {
            has_uppercase = true;
        } else if byte.is_ascii_digit() {
            has_digits = true;
        } else {
            has_symbols = true;
        }
    }

    if requirements.min_lowercase > 0 && !has_lowercase {
        return Err(ParanoidError::ImpossibleRequirements(
            "lowercase characters are required but missing from the charset".to_string(),
        ));
    }
    if requirements.min_uppercase > 0 && !has_uppercase {
        return Err(ParanoidError::ImpossibleRequirements(
            "uppercase characters are required but missing from the charset".to_string(),
        ));
    }
    if requirements.min_digits > 0 && !has_digits {
        return Err(ParanoidError::ImpossibleRequirements(
            "digit characters are required but missing from the charset".to_string(),
        ));
    }
    if requirements.min_symbols > 0 && !has_symbols {
        return Err(ParanoidError::ImpossibleRequirements(
            "symbol characters are required but missing from the charset".to_string(),
        ));
    }

    Ok(())
}

pub fn sha256_hex(input: &str) -> Result<String, ParanoidError> {
    let digest = sha256(input.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn generate_password(charset: &str, length: usize) -> Result<String, ParanoidError> {
    if length == 0 || length > MAX_PASSWORD_LEN {
        return Err(ParanoidError::InvalidArguments(format!(
            "password length must be 1..{MAX_PASSWORD_LEN}"
        )));
    }
    let charset = validate_charset(charset)?;
    let charset_bytes = charset.as_bytes();
    let max_valid = (256 / charset_bytes.len()) * charset_bytes.len() - 1;
    let mut output = Vec::with_capacity(length);
    let mut buffer = Zeroizing::new(vec![0_u8; 512]);

    while output.len() < length {
        let needed = ((length - output.len()) * 2).min(buffer.len());
        rand_bytes(&mut buffer[..needed])
            .map_err(|error| ParanoidError::RandomFailure(error.to_string()))?;
        for &byte in &buffer[..needed] {
            if usize::from(byte) <= max_valid {
                output.push(charset_bytes[usize::from(byte) % charset_bytes.len()]);
                if output.len() == length {
                    break;
                }
            }
        }
    }

    String::from_utf8(output).map_err(|error| {
        ParanoidError::InvalidArguments(format!("generated non-UTF8 password: {error}"))
    })
}

pub fn generate_constrained_password(
    charset: &str,
    length: usize,
    requirements: CharRequirements,
) -> Result<String, ParanoidError> {
    let charset = validate_charset(charset)?;
    ensure_requirements_possible(&charset, length, requirements)?;

    for _ in 0..MAX_CONSTRAINED_ATTEMPTS {
        let password = generate_password(&charset, length)?;
        let counts = count_char_types(&password);
        if counts.lowercase >= requirements.min_lowercase
            && counts.uppercase >= requirements.min_uppercase
            && counts.digits >= requirements.min_digits
            && counts.symbols >= requirements.min_symbols
        {
            return Ok(password);
        }
    }

    Err(ParanoidError::ExhaustedAttempts)
}

pub fn generate_multiple(
    charset: &str,
    length: usize,
    count: usize,
    requirements: CharRequirements,
) -> Result<Vec<String>, ParanoidError> {
    if count == 0 || count > MAX_MULTI_COUNT {
        return Err(ParanoidError::InvalidArguments(format!(
            "--count must be 1..{MAX_MULTI_COUNT}"
        )));
    }

    (0..count)
        .map(|_| {
            if requirements == CharRequirements::default() {
                generate_password(charset, length)
            } else {
                generate_constrained_password(charset, length, requirements)
            }
        })
        .collect()
}

pub fn execute_request<F>(
    request: &ParanoidRequest,
    run_audit: bool,
    mut on_stage: F,
) -> Result<GenerationReport, ParanoidError>
where
    F: FnMut(AuditStage),
{
    let resolved = request.resolve()?;
    let raw_passwords = generate_multiple(
        &resolved.charset,
        resolved.length,
        resolved.count,
        resolved.requirements,
    )?;
    let entropy =
        compute_entropy_metrics(resolved.charset.len(), resolved.length, resolved.batch_size);
    let passwords = inspect_generated_passwords(&resolved, &raw_passwords, entropy.total_entropy)?;

    let audit = if run_audit {
        Some(run_audit_summary(
            &resolved,
            &passwords,
            entropy,
            &mut on_stage,
        )?)
    } else {
        None
    };

    Ok(GenerationReport {
        request: resolved,
        passwords,
        audit,
    })
}

pub fn run_audit_summary<F>(
    request: &ResolvedRequest,
    passwords: &[GeneratedPassword],
    entropy: EntropyMetrics,
    on_stage: &mut F,
) -> Result<AuditSummary, ParanoidError>
where
    F: FnMut(AuditStage),
{
    let charset = request.charset.as_bytes();
    let charset_len = charset.len();
    let rejection_max_valid = (256 / charset_len) * charset_len - 1;

    on_stage(AuditStage::Generate);

    on_stage(AuditStage::ChiSquared);
    let mut audit_batch = Vec::with_capacity(request.batch_size);
    for _ in 0..request.batch_size {
        audit_batch.push(generate_password(&request.charset, request.length)?);
    }
    let joined = audit_batch.concat();
    let (chi2_statistic, chi2_df, chi2_p_value) = chi_squared(
        &joined,
        request.batch_size,
        request.length,
        &request.charset,
    )?;
    let chi2_pass = chi2_p_value > 0.01;

    on_stage(AuditStage::SerialCorrelation);
    let serial_correlation = serial_correlation(joined.as_bytes());
    let serial_pass = serial_correlation.abs() < 0.05;

    on_stage(AuditStage::CollisionDetection);
    let duplicates = count_collisions(&audit_batch)?;
    let collision_pass = duplicates == 0;

    on_stage(AuditStage::EntropyProofs);
    on_stage(AuditStage::PatternDetection);
    let passwords_all_pass = passwords.iter().all(|password| password.all_pass);
    let selected_frameworks_pass = passwords
        .iter()
        .all(|password| password.selected_compliance_pass);

    on_stage(AuditStage::ThreatAssessment);
    let overall_pass = chi2_pass
        && serial_pass
        && collision_pass
        && passwords_all_pass
        && selected_frameworks_pass;

    on_stage(AuditStage::Complete);

    Ok(AuditSummary {
        password_length: request.length,
        charset_size: charset_len,
        chi2_statistic,
        chi2_df,
        chi2_p_value,
        chi2_pass,
        serial_correlation,
        serial_pass,
        batch_size: request.batch_size,
        duplicates,
        collision_pass,
        entropy,
        nist_memorized: entropy.total_entropy >= AUDIT_TIER_MEMORIZED,
        nist_high_value: entropy.total_entropy >= AUDIT_TIER_HIGH_VALUE,
        nist_crypto_equiv: entropy.total_entropy >= AUDIT_TIER_CRYPTO_EQUIV,
        nist_post_quantum: entropy.total_entropy >= AUDIT_TIER_POST_QUANTUM,
        rejection_max_valid,
        rejection_rate_pct: (255 - rejection_max_valid) as f64 / 256.0 * 100.0,
        passwords_all_pass,
        selected_frameworks_pass,
        overall_pass,
    })
}

fn inspect_generated_passwords(
    request: &ResolvedRequest,
    passwords: &[String],
    total_entropy: f64,
) -> Result<Vec<GeneratedPassword>, ParanoidError> {
    passwords
        .iter()
        .map(|password| inspect_generated_password(request, password, total_entropy))
        .collect()
}

fn inspect_generated_password(
    request: &ResolvedRequest,
    password: &str,
    total_entropy: f64,
) -> Result<GeneratedPassword, ParanoidError> {
    let character_counts = count_char_types(password);
    let pattern_issues = pattern_issues(password);
    let compliance = FRAMEWORKS
        .iter()
        .map(|framework| ComplianceStatus {
            id: framework.id,
            name: framework.name.to_string(),
            selected: request.selected_frameworks.contains(&framework.id),
            passed: check_compliance(request.length, total_entropy, &character_counts, framework),
        })
        .collect::<Vec<_>>();
    let selected_compliance_pass = compliance
        .iter()
        .filter(|status| status.selected)
        .all(|status| status.passed);

    Ok(GeneratedPassword {
        value: password.to_string(),
        sha256_hex: sha256_hex(password)?,
        character_counts,
        pattern_issues,
        compliance,
        selected_compliance_pass,
        all_pass: pattern_issues == 0 && selected_compliance_pass,
    })
}

fn compute_entropy_metrics(
    charset_len: usize,
    password_length: usize,
    batch_size: usize,
) -> EntropyMetrics {
    let bits_per_char = (charset_len as f64).log2();
    let total_entropy = password_length as f64 * bits_per_char;
    let log10_search_space = password_length as f64 * (charset_len as f64).log10();
    let log_seconds = log10_search_space - 2_f64.log10() - 12.0;
    let seconds_per_year: f64 = 365.25 * 24.0 * 3600.0;
    let brute_force_years = 10_f64.powf(log_seconds - seconds_per_year.log10());
    let log_space = password_length as f64 * (charset_len as f64).ln();
    let log_exp = 2.0 * (batch_size as f64).ln() - 2_f64.ln() - log_space;
    let collision_probability = log_exp.exp().clamp(0.0, 1.0);
    let passwords_for_50pct = (0.5 * (log_space + 2_f64.ln() + (2_f64.ln()).ln())).exp();

    EntropyMetrics {
        bits_per_char,
        total_entropy,
        log10_search_space,
        brute_force_years,
        collision_probability,
        passwords_for_50pct,
    }
}

pub fn count_char_types(password: &str) -> CharacterCounts {
    let mut counts = CharacterCounts::default();
    for byte in password.bytes() {
        if byte.is_ascii_lowercase() {
            counts.lowercase += 1;
        } else if byte.is_ascii_uppercase() {
            counts.uppercase += 1;
        } else if byte.is_ascii_digit() {
            counts.digits += 1;
        } else {
            counts.symbols += 1;
        }
    }
    counts
}

pub fn check_compliance(
    password_length: usize,
    total_entropy: f64,
    character_counts: &CharacterCounts,
    framework: &ComplianceFramework,
) -> bool {
    if password_length < framework.min_length {
        return false;
    }
    if total_entropy < framework.min_entropy_bits {
        return false;
    }
    if framework.require_mixed_case
        && (character_counts.lowercase == 0 || character_counts.uppercase == 0)
    {
        return false;
    }
    if framework.require_digits && character_counts.digits == 0 {
        return false;
    }
    if framework.require_symbols && character_counts.symbols == 0 {
        return false;
    }
    true
}

pub fn chi_squared(
    passwords: &str,
    num_passwords: usize,
    password_length: usize,
    charset: &str,
) -> Result<(f64, usize, f64), ParanoidError> {
    let charset = validate_charset(charset)?;
    let charset_bytes = charset.as_bytes();
    let total_chars = num_passwords * password_length;
    if total_chars == 0 {
        return Err(ParanoidError::InvalidArguments(
            "chi-squared requires at least one character".to_string(),
        ));
    }

    let mut freq = [0_usize; 256];
    for byte in passwords.bytes() {
        freq[usize::from(byte)] += 1;
    }

    let expected = total_chars as f64 / charset_bytes.len() as f64;
    let mut chi2 = 0.0;
    for byte in charset_bytes {
        let observed = freq[usize::from(*byte)] as f64;
        let diff = observed - expected;
        chi2 += diff * diff / expected;
    }

    let df = charset_bytes.len().saturating_sub(1);
    if df == 0 {
        return Ok((chi2, df, 1.0));
    }

    // TODO: HUMAN_REVIEW - verify chi-squared upper-tail interpretation and thresholding.
    let distribution = ChiSquared::new(df as f64).map_err(|error| {
        ParanoidError::InvalidArguments(format!("invalid chi-squared degrees of freedom: {error}"))
    })?;
    let p_value = (1.0 - distribution.cdf(chi2)).clamp(0.0, 1.0);
    Ok((chi2, df, p_value))
}

pub fn serial_correlation(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    // TODO: HUMAN_REVIEW - verify the serial-correlation coefficient matches the intended estimator.
    let mean = data.iter().map(|value| f64::from(*value)).sum::<f64>() / data.len() as f64;
    let numerator = data
        .windows(2)
        .map(|pair| (f64::from(pair[0]) - mean) * (f64::from(pair[1]) - mean))
        .sum::<f64>();
    let denominator = data
        .iter()
        .map(|value| {
            let delta = f64::from(*value) - mean;
            delta * delta
        })
        .sum::<f64>();
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

pub fn count_collisions(passwords: &[String]) -> Result<usize, ParanoidError> {
    let mut seen = HashSet::with_capacity(passwords.len());
    let mut duplicates = 0_usize;

    for password in passwords {
        let digest = sha256(password.as_bytes());
        if !seen.insert(digest) {
            duplicates += 1;
        }
    }

    Ok(duplicates)
}

pub fn pattern_issues(password: &str) -> usize {
    let bytes = password.as_bytes();
    let mut issues = 0_usize;

    for window in bytes.windows(3) {
        if window[0] == window[1] && window[1] == window[2] {
            issues += 1;
        }
        if window[0].saturating_add(1) == window[1] && window[1].saturating_add(1) == window[2] {
            issues += 1;
        }
    }

    let lowercase = password.to_ascii_lowercase();
    for walk in ["qwert", "asdfg", "zxcvb", "12345", "qazws", "!@#$%"] {
        if lowercase.contains(walk) {
            issues += 1;
        }
    }

    issues
}

pub fn secure_preview(password: &str) -> String {
    if password.len() <= 4 {
        return password.to_string();
    }
    let suffix = &password[password.len() - 4..];
    format!("{}{}", "•".repeat(password.len() - 4), suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors_match_nist() {
        assert_eq!(
            sha256_hex("").expect("hash"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex("abc").expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejection_boundary_matches_reference_values() {
        assert_eq!((256 / 94) * 94 - 1, 187);
        assert_eq!((256 / 62) * 62 - 1, 247);
        assert_eq!((256 / 26) * 26 - 1, 233);
        assert_eq!((256 / 10) * 10 - 1, 249);
    }

    #[test]
    fn validate_charset_sorts_and_deduplicates() {
        assert_eq!(validate_charset("cbaabc!").expect("charset"), "!abc");
        assert!(validate_charset("").is_err());
        assert!(validate_charset("\n").is_err());
    }

    #[test]
    fn generate_password_respects_charset_and_length() {
        let password = generate_password("XYZ", 64).expect("password");
        assert_eq!(password.len(), 64);
        assert!(password.chars().all(|ch| matches!(ch, 'X' | 'Y' | 'Z')));
    }

    #[test]
    fn constrained_generation_enforces_requirements() {
        let password = generate_constrained_password(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$",
            24,
            CharRequirements {
                min_lowercase: 2,
                min_uppercase: 2,
                min_digits: 2,
                min_symbols: 2,
            },
        )
        .expect("constrained password");
        let counts = count_char_types(&password);
        assert!(counts.lowercase >= 2);
        assert!(counts.uppercase >= 2);
        assert!(counts.digits >= 2);
        assert!(counts.symbols >= 2);
    }

    #[test]
    fn impossible_requirements_fail_closed() {
        let error = generate_constrained_password(
            "abc",
            4,
            CharRequirements {
                min_lowercase: 5,
                ..CharRequirements::default()
            },
        )
        .expect_err("requirements should be impossible");
        assert!(matches!(error, ParanoidError::ImpossibleRequirements(_)));
    }

    #[test]
    fn chi_squared_known_answers_hold() {
        let passwords = "abc".repeat(1_000);
        let (chi2, df, p_value) = chi_squared(&passwords, 100, 30, "abc").expect("chi2");
        assert!(chi2.abs() < 0.001);
        assert_eq!(df, 2);
        assert!(p_value > 0.5);

        let biased = "a".repeat(3_000);
        let (chi2, df, p_value) = chi_squared(&biased, 100, 30, "abc").expect("chi2");
        assert!((chi2 - 6_000.0).abs() < 0.1);
        assert_eq!(df, 2);
        assert!(p_value < 0.01);
    }

    #[test]
    fn serial_correlation_known_answers_hold() {
        assert_eq!(serial_correlation(&[b'A'; 100]), 0.0);
        let alternating = (0..100)
            .map(|idx| if idx % 2 == 0 { b'A' } else { b'z' })
            .collect::<Vec<_>>();
        assert!(serial_correlation(&alternating) < -0.9);
    }

    #[test]
    fn pattern_detection_flags_expected_sequences() {
        assert!(pattern_issues("abcXYZ") > 0);
        assert!(pattern_issues("qwerty!") > 0);
        assert_eq!(pattern_issues("A!7mZ2qR"), 0);
    }

    #[test]
    fn request_resolution_applies_framework_requirements() {
        let request = ParanoidRequest {
            length: 8,
            charset: CharsetSpec::Options(CharsetOptions {
                include_lowercase: true,
                include_uppercase: false,
                include_digits: false,
                include_symbols: false,
                include_space: false,
                exclude_ambiguous: false,
                custom_charset: None,
            }),
            selected_frameworks: vec![FrameworkId::PciDss],
            ..ParanoidRequest::default()
        };

        let resolved = request.resolve().expect("resolved request");
        assert_eq!(resolved.length, 12);
        assert!(resolved.charset.chars().any(|ch| ch.is_ascii_uppercase()));
        assert!(resolved.charset.chars().any(|ch| ch.is_ascii_digit()));
        assert!(resolved.requirements.min_uppercase >= 1);
        assert!(resolved.requirements.min_digits >= 1);
    }

    #[test]
    fn audit_pipeline_populates_compliance_and_metrics() {
        let request = ParanoidRequest {
            selected_frameworks: vec![FrameworkId::Nist, FrameworkId::PciDss],
            ..ParanoidRequest::default()
        };
        let report = execute_request(&request, true, |_| {}).expect("report");
        assert_eq!(report.passwords.len(), 1);
        let audit = report.audit.expect("audit");
        assert_eq!(report.passwords[0].value.len(), report.request.length);
        assert_eq!(audit.password_length, report.request.length);
        assert_eq!(audit.charset_size, report.request.charset.len());
        assert!(audit.entropy.total_entropy > 0.0);
        assert!(report.passwords[0].selected_compliance_pass);
        assert!(audit.passwords_all_pass);
        assert!(audit.selected_frameworks_pass);
    }

    #[test]
    fn multi_password_report_inspects_each_generated_password() {
        let request = ParanoidRequest {
            count: 3,
            selected_frameworks: vec![FrameworkId::PciDss],
            ..ParanoidRequest::default()
        };

        let report = execute_request(&request, true, |_| {}).expect("report");
        assert_eq!(report.passwords.len(), 3);
        assert!(
            report
                .passwords
                .iter()
                .all(|password| !password.sha256_hex.is_empty())
        );
        assert!(
            report
                .passwords
                .iter()
                .all(|password| password.compliance.iter().any(|status| status.selected))
        );
        assert!(report.audit.expect("audit").passwords_all_pass);
    }
}
