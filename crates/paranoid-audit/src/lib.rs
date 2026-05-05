use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    fs::OpenOptions,
    io::{BufWriter, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const AUDIT_HASH_CHAIN_VERSION: u16 = 1;
pub const DEFAULT_AUDIT_OPERATION_ID: &str = "pp.operation.v1.local";
const PARANOID_AUDIT_DEVICE_ENDPOINT: &str = "PARANOID_AUDIT_DEVICE_ENDPOINT";
const PARANOID_AUDIT_DEVICE_ID: &str = "PARANOID_AUDIT_DEVICE_ID";
const PARANOID_AUDIT_DEVICE_MTLS_CERT: &str = "PARANOID_AUDIT_DEVICE_MTLS_CERT";
const PARANOID_AUDIT_DEVICE_MTLS_KEY: &str = "PARANOID_AUDIT_DEVICE_MTLS_KEY";
const PARANOID_AUDIT_DEVICE_CA_CERT: &str = "PARANOID_AUDIT_DEVICE_CA_CERT";
const PARANOID_AUDIT_DEVICE_PROBE: &str = "PARANOID_AUDIT_DEVICE_PROBE";
const EXTERNAL_AUDIT_DEVICE_DEFAULT_ID: &str = "external_audit_device";
const EXTERNAL_AUDIT_DEVICE_TCP_PROBE: &str = "tcp-connect";
const EXTERNAL_AUDIT_DEVICE_PROBE_DISABLED: &str = "disabled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkKind {
    JsonlFile,
    ExternalDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkStatus {
    NotConfigured,
    Ready,
    Unavailable,
    Unverified,
}

// TODO: AI_REVIEW - confirm external audit-device posture and health semantics do not overstate sink availability or federal audit coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSinkHealth {
    pub schema_version: u16,
    pub kind: AuditSinkKind,
    pub status: AuditSinkStatus,
    pub configured: bool,
    pub writable: bool,
    pub append_mode: bool,
    pub redaction_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

impl AuditSinkHealth {
    pub fn not_configured_jsonl() -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::JsonlFile,
            status: AuditSinkStatus::NotConfigured,
            configured: false,
            writable: false,
            append_mode: true,
            redaction_mode: "strict_marker".to_string(),
            path: None,
            endpoint: None,
            provider_id: None,
            evidence_source: None,
            failure: None,
        }
    }

    pub fn ready_jsonl(path: Option<String>) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::JsonlFile,
            status: AuditSinkStatus::Ready,
            configured: true,
            writable: true,
            append_mode: true,
            redaction_mode: "strict_marker".to_string(),
            path,
            endpoint: None,
            provider_id: None,
            evidence_source: None,
            failure: None,
        }
    }

    pub fn unavailable_jsonl(path: Option<String>, failure: impl Into<String>) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::JsonlFile,
            status: AuditSinkStatus::Unavailable,
            configured: true,
            writable: false,
            append_mode: true,
            redaction_mode: "strict_marker".to_string(),
            path,
            endpoint: None,
            provider_id: None,
            evidence_source: None,
            failure: Some(failure.into()),
        }
    }

    pub fn not_configured_external_device() -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::ExternalDevice,
            status: AuditSinkStatus::NotConfigured,
            configured: false,
            writable: false,
            append_mode: false,
            redaction_mode: "strict_marker".to_string(),
            path: None,
            endpoint: None,
            provider_id: None,
            evidence_source: Some("environment".to_string()),
            failure: None,
        }
    }

    pub fn unavailable_external_device(
        provider_id: impl Into<String>,
        endpoint: impl Into<String>,
        failure: impl Into<String>,
    ) -> Self {
        Self::unavailable_external_device_with_evidence_source(
            provider_id,
            endpoint,
            "environment",
            failure,
        )
    }

    pub fn unavailable_external_device_with_evidence_source(
        provider_id: impl Into<String>,
        endpoint: impl Into<String>,
        evidence_source: impl Into<String>,
        failure: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::ExternalDevice,
            status: AuditSinkStatus::Unavailable,
            configured: true,
            writable: false,
            append_mode: false,
            redaction_mode: "strict_marker".to_string(),
            path: None,
            endpoint: Some(endpoint.into()),
            provider_id: Some(provider_id.into()),
            evidence_source: Some(evidence_source.into()),
            failure: Some(failure.into()),
        }
    }

    pub fn unverified_external_device(
        provider_id: impl Into<String>,
        endpoint: impl Into<String>,
        failure: impl Into<String>,
    ) -> Self {
        Self::unverified_external_device_with_evidence_source(
            provider_id,
            endpoint,
            "environment",
            failure,
        )
    }

    pub fn unverified_external_device_with_evidence_source(
        provider_id: impl Into<String>,
        endpoint: impl Into<String>,
        evidence_source: impl Into<String>,
        failure: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::ExternalDevice,
            status: AuditSinkStatus::Unverified,
            configured: true,
            writable: false,
            append_mode: false,
            redaction_mode: "strict_marker".to_string(),
            path: None,
            endpoint: Some(endpoint.into()),
            provider_id: Some(provider_id.into()),
            evidence_source: Some(evidence_source.into()),
            failure: Some(failure.into()),
        }
    }

    pub fn ready_external_device(
        provider_id: impl Into<String>,
        endpoint: impl Into<String>,
        evidence_source: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            kind: AuditSinkKind::ExternalDevice,
            status: AuditSinkStatus::Ready,
            configured: true,
            writable: true,
            append_mode: true,
            redaction_mode: "strict_marker".to_string(),
            path: None,
            endpoint: Some(endpoint.into()),
            provider_id: Some(provider_id.into()),
            evidence_source: Some(evidence_source.into()),
            failure: None,
        }
    }

    pub fn is_available(&self) -> bool {
        self.status == AuditSinkStatus::Ready && self.configured && self.writable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuditDeviceConfig {
    provider_id: String,
    endpoint: String,
    mtls_certificate_evidence: String,
    mtls_private_key_evidence: String,
    mtls_ca_certificate_evidence: String,
}

impl ExternalAuditDeviceConfig {
    pub fn new(
        provider_id: impl Into<String>,
        endpoint: impl Into<String>,
        mtls_certificate_evidence: impl Into<String>,
        mtls_private_key_evidence: impl Into<String>,
        mtls_ca_certificate_evidence: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            endpoint: endpoint.into(),
            mtls_certificate_evidence: mtls_certificate_evidence.into(),
            mtls_private_key_evidence: mtls_private_key_evidence.into(),
            mtls_ca_certificate_evidence: mtls_ca_certificate_evidence.into(),
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn mtls_certificate_evidence(&self) -> &str {
        &self.mtls_certificate_evidence
    }

    pub fn mtls_private_key_evidence(&self) -> &str {
        &self.mtls_private_key_evidence
    }

    pub fn mtls_ca_certificate_evidence(&self) -> &str {
        &self.mtls_ca_certificate_evidence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuditDeviceProbeStatus {
    Ready,
    Unverified,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuditDeviceProbeResult {
    status: ExternalAuditDeviceProbeStatus,
    evidence_source: String,
    failure: Option<String>,
}

impl ExternalAuditDeviceProbeResult {
    pub fn ready(evidence_source: impl Into<String>) -> Self {
        Self {
            status: ExternalAuditDeviceProbeStatus::Ready,
            evidence_source: evidence_source.into(),
            failure: None,
        }
    }

    pub fn unverified(evidence_source: impl Into<String>, failure: impl Into<String>) -> Self {
        Self {
            status: ExternalAuditDeviceProbeStatus::Unverified,
            evidence_source: evidence_source.into(),
            failure: Some(failure.into()),
        }
    }

    pub fn unavailable(evidence_source: impl Into<String>, failure: impl Into<String>) -> Self {
        Self {
            status: ExternalAuditDeviceProbeStatus::Unavailable,
            evidence_source: evidence_source.into(),
            failure: Some(failure.into()),
        }
    }
}

pub trait ExternalAuditDeviceProbe {
    fn probe(&mut self, config: &ExternalAuditDeviceConfig) -> ExternalAuditDeviceProbeResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisabledExternalAuditDeviceProbe {
    failure: String,
}

impl Default for DisabledExternalAuditDeviceProbe {
    fn default() -> Self {
        Self {
            failure:
                "external audit-device live probe disabled; configured mTLS material is evidence only"
                    .to_string(),
        }
    }
}

impl DisabledExternalAuditDeviceProbe {
    pub fn unsupported_mode(mode: impl Into<String>) -> Self {
        Self {
            failure: format!(
                "unsupported external audit-device probe mode: {}",
                mode.into()
            ),
        }
    }
}

impl ExternalAuditDeviceProbe for DisabledExternalAuditDeviceProbe {
    fn probe(&mut self, _config: &ExternalAuditDeviceConfig) -> ExternalAuditDeviceProbeResult {
        ExternalAuditDeviceProbeResult::unverified(
            EXTERNAL_AUDIT_DEVICE_PROBE_DISABLED,
            self.failure.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectExternalAuditDeviceProbe {
    timeout: Duration,
}

impl Default for TcpConnectExternalAuditDeviceProbe {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
        }
    }
}

impl TcpConnectExternalAuditDeviceProbe {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl ExternalAuditDeviceProbe for TcpConnectExternalAuditDeviceProbe {
    fn probe(&mut self, config: &ExternalAuditDeviceConfig) -> ExternalAuditDeviceProbeResult {
        let addresses = match socket_addresses_from_endpoint(config.endpoint()) {
            Ok(addresses) => addresses,
            Err(error) => {
                return ExternalAuditDeviceProbeResult::unavailable(
                    EXTERNAL_AUDIT_DEVICE_TCP_PROBE,
                    error,
                );
            }
        };

        let mut failures = Vec::new();
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.timeout) {
                Ok(_stream) => {
                    return ExternalAuditDeviceProbeResult::unverified(
                        EXTERNAL_AUDIT_DEVICE_TCP_PROBE,
                        "live tcp-connect probe reached endpoint; audit write acknowledgement is not implemented",
                    );
                }
                Err(error) => failures.push(format!("{address}: {error}")),
            }
        }

        ExternalAuditDeviceProbeResult::unavailable(
            EXTERNAL_AUDIT_DEVICE_TCP_PROBE,
            format!("live tcp-connect probe failed: {}", failures.join("; ")),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSurface {
    Core,
    Vault,
    Cli,
    Tui,
    Gui,
    Ops,
    SupplyChain,
}

impl AuditSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Vault => "vault",
            Self::Cli => "cli",
            Self::Tui => "tui",
            Self::Gui => "gui",
            Self::Ops => "ops",
            Self::SupplyChain => "supply_chain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Started,
    Success,
    Review,
    Failure,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Notice,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSubject {
    PasswordGeneration,
    StatisticalAudit,
    ComplianceCheck,
    VaultOperation,
    ReleaseAssurance,
    Automation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: u16,
    pub operation_id: String,
    pub event_id: String,
    pub sequence: u64,
    pub occurred_at_epoch_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_error: Option<String>,
    pub surface: AuditSurface,
    pub subject: AuditSubject,
    pub action: String,
    pub outcome: AuditOutcome,
    pub severity: AuditSeverity,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl AuditEvent {
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn redact_attributes(&mut self, redactor: &AuditRedactor) {
        self.attributes = redactor.redact_attributes(&self.attributes);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrail {
    operation_id: String,
    events: Vec<AuditEvent>,
    next_sequence: u64,
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::for_operation(DEFAULT_AUDIT_OPERATION_ID)
    }
}

impl AuditTrail {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_operation(operation_id: impl Into<String>) -> Self {
        Self {
            operation_id: operation_id.into(),
            events: Vec::new(),
            next_sequence: 0,
        }
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn record(
        &mut self,
        surface: AuditSurface,
        subject: AuditSubject,
        action: impl Into<String>,
        outcome: AuditOutcome,
        severity: AuditSeverity,
        message: impl Into<String>,
    ) -> &mut AuditEvent {
        self.next_sequence += 1;
        let sequence = self.next_sequence;
        let timestamp = current_epoch_ms();
        let event = AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation_id: self.operation_id.clone(),
            event_id: format!("{}.event.{}", self.operation_id, sequence),
            sequence,
            occurred_at_epoch_ms: timestamp.epoch_ms,
            timestamp_error: timestamp.error,
            surface,
            subject,
            action: action.into(),
            outcome,
            severity,
            message: message.into(),
            attributes: BTreeMap::new(),
        };
        self.events.push(event);
        self.events
            .last_mut()
            .expect("record just pushed an audit event")
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<AuditEvent> {
        self.events
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn to_json_lines(&self) -> Result<String, AuditError> {
        let mut output = String::new();
        for event in &self.events {
            output.push_str(&serde_json::to_string(event)?);
            output.push('\n');
        }
        Ok(output)
    }

    pub fn to_hash_chain(&self) -> Result<Vec<HashChainedAuditEvent>, AuditError> {
        hash_chain_events(&self.events)
    }

    pub fn write_jsonl(&self, path: impl AsRef<Path>) -> Result<(), AuditError> {
        write_events_jsonl(path, &self.events)
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to serialize audit event: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit sink io failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit hash failure: {0}")]
    Hash(String),
    #[error("audit hash chain mismatch at event {event_id}")]
    HashChainMismatch { event_id: String },
}

pub trait AuditSink {
    fn record_event(&mut self, event: &AuditEvent) -> Result<(), AuditError>;

    fn record_events(&mut self, events: &[AuditEvent]) -> Result<(), AuditError> {
        for event in events {
            self.record_event(event)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), AuditError>;
}

pub struct JsonlFileAuditSink {
    writer: BufWriter<std::fs::File>,
}

impl JsonlFileAuditSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }
}

impl AuditSink for JsonlFileAuditSink {
    fn record_event(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), AuditError> {
        self.writer.flush()?;
        Ok(())
    }
}

pub fn write_events_jsonl(path: impl AsRef<Path>, events: &[AuditEvent]) -> Result<(), AuditError> {
    let mut sink = JsonlFileAuditSink::open(path)?;
    sink.record_events(events)?;
    sink.flush()
}

pub fn assess_optional_jsonl_file_audit_sink(path: Option<&Path>) -> AuditSinkHealth {
    let Some(path) = path else {
        return AuditSinkHealth::not_configured_jsonl();
    };
    let display_path = Some(path.display().to_string());
    match JsonlFileAuditSink::open(path).and_then(|mut sink| sink.flush()) {
        Ok(()) => AuditSinkHealth::ready_jsonl(display_path),
        Err(error) => AuditSinkHealth::unavailable_jsonl(display_path, error.to_string()),
    }
}

pub fn assess_external_audit_device_from_environment() -> AuditSinkHealth {
    assess_external_audit_device_from_lookup(|name| {
        // Non-Unicode values cannot be used as UTF-8 paths, so they are missing evidence.
        env::var(name).ok()
    })
}

fn assess_external_audit_device_from_lookup(
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> AuditSinkHealth {
    let probe_mode = non_empty_lookup_value(value_for(PARANOID_AUDIT_DEVICE_PROBE))
        .unwrap_or_else(|| EXTERNAL_AUDIT_DEVICE_PROBE_DISABLED.to_string());
    match probe_mode.as_str() {
        EXTERNAL_AUDIT_DEVICE_TCP_PROBE => {
            let mut probe = TcpConnectExternalAuditDeviceProbe::default();
            assess_external_audit_device_from_lookup_with_probe(value_for, &mut probe)
        }
        EXTERNAL_AUDIT_DEVICE_PROBE_DISABLED => {
            let mut probe = DisabledExternalAuditDeviceProbe::default();
            assess_external_audit_device_from_lookup_with_probe(value_for, &mut probe)
        }
        unsupported => {
            let mut probe = DisabledExternalAuditDeviceProbe::unsupported_mode(unsupported);
            assess_external_audit_device_from_lookup_with_probe(value_for, &mut probe)
        }
    }
}

pub fn assess_external_audit_device_from_lookup_with_probe(
    mut value_for: impl FnMut(&str) -> Option<String>,
    probe: &mut impl ExternalAuditDeviceProbe,
) -> AuditSinkHealth {
    let Some(endpoint) = non_empty_lookup_value(value_for(PARANOID_AUDIT_DEVICE_ENDPOINT)) else {
        return AuditSinkHealth::not_configured_external_device();
    };
    let provider_id = non_empty_lookup_value(value_for(PARANOID_AUDIT_DEVICE_ID))
        .unwrap_or_else(|| EXTERNAL_AUDIT_DEVICE_DEFAULT_ID.to_string());

    let required_mtls_vars = BTreeMap::from([
        (
            PARANOID_AUDIT_DEVICE_MTLS_CERT,
            non_empty_lookup_value(value_for(PARANOID_AUDIT_DEVICE_MTLS_CERT)),
        ),
        (
            PARANOID_AUDIT_DEVICE_MTLS_KEY,
            non_empty_lookup_value(value_for(PARANOID_AUDIT_DEVICE_MTLS_KEY)),
        ),
        (
            PARANOID_AUDIT_DEVICE_CA_CERT,
            non_empty_lookup_value(value_for(PARANOID_AUDIT_DEVICE_CA_CERT)),
        ),
    ]);
    let mut missing_mtls = Vec::new();
    for (name, value) in &required_mtls_vars {
        if value.is_none() {
            missing_mtls.push(*name);
        }
    }
    if !missing_mtls.is_empty() {
        return AuditSinkHealth::unavailable_external_device(
            provider_id,
            endpoint,
            format!("missing mTLS evidence: {}", missing_mtls.join(", ")),
        );
    }

    let config = ExternalAuditDeviceConfig::new(
        provider_id,
        endpoint,
        required_mtls_vars
            .get(PARANOID_AUDIT_DEVICE_MTLS_CERT)
            .and_then(Option::clone)
            .unwrap_or_default(),
        required_mtls_vars
            .get(PARANOID_AUDIT_DEVICE_MTLS_KEY)
            .and_then(Option::clone)
            .unwrap_or_default(),
        required_mtls_vars
            .get(PARANOID_AUDIT_DEVICE_CA_CERT)
            .and_then(Option::clone)
            .unwrap_or_default(),
    );
    let probe_result = probe.probe(&config);
    match probe_result.status {
        ExternalAuditDeviceProbeStatus::Ready => AuditSinkHealth::ready_external_device(
            config.provider_id,
            config.endpoint,
            probe_result.evidence_source,
        ),
        ExternalAuditDeviceProbeStatus::Unverified => {
            AuditSinkHealth::unverified_external_device_with_evidence_source(
                config.provider_id,
                config.endpoint,
                probe_result.evidence_source,
                probe_result.failure.unwrap_or_else(|| {
                    "external audit-device probe did not return readiness".to_string()
                }),
            )
        }
        ExternalAuditDeviceProbeStatus::Unavailable => {
            AuditSinkHealth::unavailable_external_device_with_evidence_source(
                config.provider_id,
                config.endpoint,
                probe_result.evidence_source,
                probe_result
                    .failure
                    .unwrap_or_else(|| "external audit-device probe failed".to_string()),
            )
        }
    }
}

fn non_empty_lookup_value(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

fn socket_addresses_from_endpoint(endpoint: &str) -> Result<Vec<std::net::SocketAddr>, String> {
    let authority = endpoint_authority(endpoint)?;
    let addresses: Vec<std::net::SocketAddr> = authority
        .to_socket_addrs()
        .map_err(|error| format!("invalid external audit-device endpoint {endpoint:?}: {error}"))?
        .collect();
    if addresses.is_empty() {
        return Err(format!(
            "invalid external audit-device endpoint {endpoint:?}: no socket addresses resolved"
        ));
    }
    Ok(addresses)
}

fn endpoint_authority(endpoint: &str) -> Result<String, String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err("external audit-device endpoint is empty".to_string());
    }
    let without_scheme = match trimmed.split_once("://") {
        Some((scheme, rest)) => match scheme {
            "mtls" | "tls" | "tcp" => rest,
            unsupported => {
                return Err(format!(
                    "unsupported external audit-device endpoint scheme: {unsupported}"
                ));
            }
        },
        None => trimmed,
    };
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    if authority.is_empty() || !authority.contains(':') {
        return Err(format!(
            "external audit-device endpoint {endpoint:?} must include host:port"
        ));
    }
    Ok(authority.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRedactor {
    sensitive_keys: Vec<&'static str>,
}

impl Default for AuditRedactor {
    fn default() -> Self {
        Self {
            sensitive_keys: vec![
                "password",
                "passwords",
                "secret",
                "recovery_secret",
                "recovery_phrase",
                "mnemonic",
                "mnemonic_phrase",
                "private_key",
                "key_passphrase",
                "master_key",
                "unwrapped_key",
                "plaintext",
                "value",
            ],
        }
    }
}

impl AuditRedactor {
    pub fn strict() -> Self {
        Self::default()
    }

    pub fn redact_attributes(
        &self,
        attributes: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        attributes
            .iter()
            .map(|(key, value)| {
                if self.is_sensitive_key(key) {
                    (key.clone(), "[redacted]".to_string())
                } else {
                    (key.clone(), value.clone())
                }
            })
            .collect()
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        let normalized = key.to_ascii_lowercase();
        self.sensitive_keys
            .iter()
            .any(|sensitive| matches_sensitive_key(&normalized, sensitive))
    }
}

fn matches_sensitive_key(normalized_key: &str, sensitive_key: &str) -> bool {
    if normalized_key == sensitive_key {
        return true;
    }
    if normalized_key
        .strip_suffix(sensitive_key)
        .is_some_and(|prefix| prefix.ends_with('_'))
    {
        return true;
    }
    normalized_key
        .match_indices(sensitive_key)
        .any(|(offset, _)| normalized_key[offset + sensitive_key.len()..].starts_with('_'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashChainedAuditEvent {
    pub chain_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash_hex: Option<String>,
    pub event_hash_hex: String,
    pub event: AuditEvent,
}

pub fn hash_chain_events(events: &[AuditEvent]) -> Result<Vec<HashChainedAuditEvent>, AuditError> {
    let mut previous_hash_hex: Option<String> = None;
    let mut chained = Vec::with_capacity(events.len());

    for event in events {
        let event_hash_hex = hash_chain_event_hash(previous_hash_hex.as_deref(), event)?;
        chained.push(HashChainedAuditEvent {
            chain_version: AUDIT_HASH_CHAIN_VERSION,
            previous_hash_hex: previous_hash_hex.clone(),
            event_hash_hex: event_hash_hex.clone(),
            event: event.clone(),
        });
        previous_hash_hex = Some(event_hash_hex);
    }

    Ok(chained)
}

pub fn verify_hash_chain(events: &[HashChainedAuditEvent]) -> Result<(), AuditError> {
    let mut previous_hash_hex: Option<String> = None;
    for event in events {
        if event.previous_hash_hex != previous_hash_hex {
            return Err(AuditError::HashChainMismatch {
                event_id: event.event.event_id.clone(),
            });
        }
        let expected = hash_chain_event_hash(previous_hash_hex.as_deref(), &event.event)?;
        if event.event_hash_hex != expected {
            return Err(AuditError::HashChainMismatch {
                event_id: event.event.event_id.clone(),
            });
        }
        previous_hash_hex = Some(event.event_hash_hex.clone());
    }
    Ok(())
}

fn hash_chain_event_hash(
    previous_hash_hex: Option<&str>,
    event: &AuditEvent,
) -> Result<String, AuditError> {
    let event_json = serde_json::to_string(event)?;
    let chain_input = format!(
        "paranoid-passwd.audit-chain.v{AUDIT_HASH_CHAIN_VERSION}\nprevious={}\nevent={event_json}",
        previous_hash_hex.unwrap_or("genesis")
    );
    paranoid_core::sha256_hex(&chain_input).map_err(|error| AuditError::Hash(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditTimestamp {
    epoch_ms: u128,
    error: Option<String>,
}

fn current_epoch_ms() -> AuditTimestamp {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => AuditTimestamp {
            epoch_ms: duration.as_millis(),
            error: None,
        },
        Err(error) => AuditTimestamp {
            epoch_ms: 0,
            error: Some(format!(
                "system_clock_before_unix_epoch_by_{}_ms",
                error.duration().as_millis()
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_trail_uses_deterministic_sequence_ids_without_randomness() {
        let mut trail = AuditTrail::for_operation("pp.operation.v1.test");
        trail.record(
            AuditSurface::Ops,
            AuditSubject::Automation,
            "start",
            AuditOutcome::Started,
            AuditSeverity::Info,
            "operation started",
        );
        trail.record(
            AuditSurface::Ops,
            AuditSubject::Automation,
            "finish",
            AuditOutcome::Success,
            AuditSeverity::Notice,
            "operation finished",
        );

        assert_eq!(trail.operation_id(), "pp.operation.v1.test");
        assert_eq!(trail.events()[0].operation_id, "pp.operation.v1.test");
        assert_eq!(trail.events()[0].event_id, "pp.operation.v1.test.event.1");
        assert_eq!(trail.events()[1].event_id, "pp.operation.v1.test.event.2");
        assert_eq!(trail.events()[1].sequence, 2);
    }

    #[test]
    fn audit_trail_serializes_as_json_lines() {
        let mut trail = AuditTrail::new();
        trail.record(
            AuditSurface::Cli,
            AuditSubject::PasswordGeneration,
            "generate",
            AuditOutcome::Success,
            AuditSeverity::Notice,
            "generated one password",
        );

        let lines = trail.to_json_lines().expect("serialize");
        assert!(lines.contains("\"schema_version\":1"));
        assert!(lines.contains("\"surface\":\"cli\""));
        assert_eq!(lines.lines().count(), 1);
    }

    #[test]
    fn redactor_removes_secret_attributes_without_hashing_them() {
        let redactor = AuditRedactor::strict();
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "password".to_string(),
            "correct horse battery staple".to_string(),
        );
        attributes.insert("api_secret_value".to_string(), "token".to_string());
        attributes.insert("ssh_private_key".to_string(), "key material".to_string());
        attributes.insert("vault_path".to_string(), "/tmp/vault.db".to_string());

        let redacted = redactor.redact_attributes(&attributes);

        assert_eq!(
            redacted.get("password").map(String::as_str),
            Some("[redacted]")
        );
        assert_eq!(
            redacted.get("api_secret_value").map(String::as_str),
            Some("[redacted]")
        );
        assert_eq!(
            redacted.get("ssh_private_key").map(String::as_str),
            Some("[redacted]")
        );
        assert_eq!(
            redacted.get("vault_path").map(String::as_str),
            Some("/tmp/vault.db")
        );
    }

    #[test]
    fn jsonl_sink_writes_required_audit_events() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("audit.jsonl");
        let mut trail = AuditTrail::for_operation("pp.operation.v1.sink-test");
        trail.record(
            AuditSurface::Cli,
            AuditSubject::Automation,
            "request",
            AuditOutcome::Started,
            AuditSeverity::Info,
            "request accepted",
        );

        trail.write_jsonl(&path).expect("write audit jsonl");
        let written = std::fs::read_to_string(path).expect("read audit jsonl");

        assert!(written.contains("\"operation_id\":\"pp.operation.v1.sink-test\""));
        assert_eq!(written.lines().count(), 1);
    }

    #[test]
    fn jsonl_sink_health_reports_ready_and_unavailable_paths() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let ready_path = tempdir.path().join("audit.jsonl");
        let missing_parent_path = tempdir.path().join("missing").join("audit.jsonl");

        let not_configured = assess_optional_jsonl_file_audit_sink(None);
        let ready = assess_optional_jsonl_file_audit_sink(Some(&ready_path));
        let unavailable = assess_optional_jsonl_file_audit_sink(Some(&missing_parent_path));

        assert_eq!(not_configured.status, AuditSinkStatus::NotConfigured);
        assert!(!not_configured.is_available());
        assert_eq!(ready.status, AuditSinkStatus::Ready);
        assert!(ready.is_available());
        assert_eq!(unavailable.status, AuditSinkStatus::Unavailable);
        assert!(!unavailable.is_available());
        assert!(unavailable.failure.is_some());
    }

    #[test]
    fn external_audit_device_health_never_claims_env_only_readiness() {
        let not_configured = AuditSinkHealth::not_configured_external_device();
        assert_eq!(not_configured.kind, AuditSinkKind::ExternalDevice);
        assert_eq!(not_configured.status, AuditSinkStatus::NotConfigured);
        assert!(!not_configured.is_available());

        let unavailable = AuditSinkHealth::unavailable_external_device(
            "siem-primary",
            "mtls://audit.example.invalid:6514",
            "missing mTLS evidence: PARANOID_AUDIT_DEVICE_MTLS_CERT",
        );
        assert_eq!(unavailable.status, AuditSinkStatus::Unavailable);
        assert!(unavailable.configured);
        assert!(!unavailable.is_available());
        assert_eq!(
            unavailable.endpoint.as_deref(),
            Some("mtls://audit.example.invalid:6514")
        );

        let unverified = AuditSinkHealth::unverified_external_device(
            "siem-primary",
            "mtls://audit.example.invalid:6514",
            "probe not implemented",
        );
        assert_eq!(unverified.status, AuditSinkStatus::Unverified);
        assert!(unverified.configured);
        assert!(!unverified.is_available());
    }

    #[test]
    fn ready_external_device_requires_explicit_health_evidence() {
        let ready = AuditSinkHealth::ready_external_device(
            "siem-primary",
            "mtls://audit.example.invalid:6514",
            "test",
        );

        assert_eq!(ready.kind, AuditSinkKind::ExternalDevice);
        assert_eq!(ready.status, AuditSinkStatus::Ready);
        assert!(ready.is_available());
        assert_eq!(ready.evidence_source.as_deref(), Some("test"));
    }

    #[test]
    fn external_audit_device_environment_lookup_never_claims_ready() {
        fn assess_from(values: &[(&str, &str)]) -> AuditSinkHealth {
            let values: BTreeMap<&str, String> = values
                .iter()
                .map(|(name, value)| (*name, (*value).to_string()))
                .collect();
            assess_external_audit_device_from_lookup(|name| values.get(name).cloned())
        }

        let not_configured = assess_from(&[]);
        assert_eq!(
            not_configured,
            AuditSinkHealth::not_configured_external_device()
        );
        assert!(!not_configured.is_available());

        let missing_mtls = assess_from(&[(
            PARANOID_AUDIT_DEVICE_ENDPOINT,
            "mtls://audit.example.invalid:6514",
        )]);
        assert_eq!(missing_mtls.status, AuditSinkStatus::Unavailable);
        assert!(!missing_mtls.is_available());
        assert!(
            missing_mtls
                .failure
                .as_deref()
                .unwrap_or_default()
                .contains(PARANOID_AUDIT_DEVICE_MTLS_CERT)
        );

        let empty_mtls_is_missing = assess_from(&[
            (
                PARANOID_AUDIT_DEVICE_ENDPOINT,
                "mtls://audit.example.invalid:6514",
            ),
            (PARANOID_AUDIT_DEVICE_MTLS_CERT, ""),
            (PARANOID_AUDIT_DEVICE_MTLS_KEY, "/tmp/device.key"),
            (PARANOID_AUDIT_DEVICE_CA_CERT, "/tmp/ca.crt"),
        ]);
        assert_eq!(empty_mtls_is_missing.status, AuditSinkStatus::Unavailable);
        assert!(!empty_mtls_is_missing.is_available());

        let unverified = assess_from(&[
            (
                PARANOID_AUDIT_DEVICE_ENDPOINT,
                "mtls://audit.example.invalid:6514",
            ),
            (PARANOID_AUDIT_DEVICE_MTLS_CERT, "/tmp/device.crt"),
            (PARANOID_AUDIT_DEVICE_MTLS_KEY, "/tmp/device.key"),
            (PARANOID_AUDIT_DEVICE_CA_CERT, "/tmp/ca.crt"),
        ]);
        assert_eq!(unverified.status, AuditSinkStatus::Unverified);
        assert_eq!(
            unverified.provider_id.as_deref(),
            Some("external_audit_device")
        );
        assert_eq!(
            unverified.evidence_source.as_deref(),
            Some(EXTERNAL_AUDIT_DEVICE_PROBE_DISABLED)
        );
        assert!(
            unverified
                .failure
                .as_deref()
                .unwrap_or_default()
                .contains("live probe disabled")
        );
        assert!(!unverified.is_available());
    }

    #[test]
    fn external_audit_device_tcp_probe_reaches_open_listener_without_claiming_ready() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let endpoint = format!("mtls://{}", listener.local_addr().expect("listener addr"));
        let accept_thread = std::thread::spawn(move || {
            let _accepted = listener.accept().expect("accept tcp probe");
        });

        let values = BTreeMap::from([
            (
                PARANOID_AUDIT_DEVICE_PROBE,
                EXTERNAL_AUDIT_DEVICE_TCP_PROBE.to_string(),
            ),
            (PARANOID_AUDIT_DEVICE_ENDPOINT, endpoint),
            (
                PARANOID_AUDIT_DEVICE_MTLS_CERT,
                "/tmp/device.crt".to_string(),
            ),
            (
                PARANOID_AUDIT_DEVICE_MTLS_KEY,
                "/tmp/device.key".to_string(),
            ),
            (PARANOID_AUDIT_DEVICE_CA_CERT, "/tmp/ca.crt".to_string()),
        ]);
        let health = assess_external_audit_device_from_lookup(|name| values.get(name).cloned());
        accept_thread.join().expect("accept thread joins");

        assert_eq!(health.status, AuditSinkStatus::Unverified);
        assert_eq!(
            health.evidence_source.as_deref(),
            Some(EXTERNAL_AUDIT_DEVICE_TCP_PROBE)
        );
        assert!(
            health
                .failure
                .as_deref()
                .unwrap_or_default()
                .contains("reached endpoint")
        );
        assert!(!health.is_available());
    }

    #[test]
    fn external_audit_device_probe_can_mark_ready_only_with_explicit_ack() {
        struct ReadyProbe;

        impl ExternalAuditDeviceProbe for ReadyProbe {
            fn probe(
                &mut self,
                _config: &ExternalAuditDeviceConfig,
            ) -> ExternalAuditDeviceProbeResult {
                ExternalAuditDeviceProbeResult::ready("test-ack")
            }
        }

        let values = BTreeMap::from([
            (
                PARANOID_AUDIT_DEVICE_ENDPOINT,
                "mtls://audit.example.invalid:6514".to_string(),
            ),
            (PARANOID_AUDIT_DEVICE_ID, "siem-primary".to_string()),
            (
                PARANOID_AUDIT_DEVICE_MTLS_CERT,
                "/tmp/device.crt".to_string(),
            ),
            (
                PARANOID_AUDIT_DEVICE_MTLS_KEY,
                "/tmp/device.key".to_string(),
            ),
            (PARANOID_AUDIT_DEVICE_CA_CERT, "/tmp/ca.crt".to_string()),
        ]);
        let mut probe = ReadyProbe;

        let health = assess_external_audit_device_from_lookup_with_probe(
            |name| values.get(name).cloned(),
            &mut probe,
        );

        assert_eq!(health.status, AuditSinkStatus::Ready);
        assert_eq!(health.evidence_source.as_deref(), Some("test-ack"));
        assert!(health.is_available());
    }

    #[test]
    fn hash_chain_detects_tampered_events() {
        let mut trail = AuditTrail::for_operation("pp.operation.v1.hash-test");
        trail.record(
            AuditSurface::Ops,
            AuditSubject::Automation,
            "request",
            AuditOutcome::Started,
            AuditSeverity::Info,
            "request accepted",
        );
        trail.record(
            AuditSurface::Ops,
            AuditSubject::Automation,
            "response",
            AuditOutcome::Success,
            AuditSeverity::Notice,
            "request completed",
        );

        let mut chain = trail.to_hash_chain().expect("hash chain");
        verify_hash_chain(&chain).expect("valid chain");
        chain[1].event.message = "tampered".to_string();

        assert!(matches!(
            verify_hash_chain(&chain),
            Err(AuditError::HashChainMismatch { .. })
        ));
    }
}
