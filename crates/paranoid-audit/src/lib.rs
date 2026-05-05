use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_AUDIT_OPERATION_ID: &str = "pp.operation.v1.local";

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
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to serialize audit event: {0}")]
    Json(#[from] serde_json::Error),
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
}
