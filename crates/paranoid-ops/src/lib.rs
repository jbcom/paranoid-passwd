use paranoid_audit::{
    AUDIT_SCHEMA_VERSION, AuditEvent, AuditOutcome, AuditSeverity, AuditSubject, AuditSurface,
    AuditTrail,
};
use paranoid_core::{AuditStage, AuditSummary, GenerationReport, ParanoidError, ParanoidRequest};
use serde::{Deserialize, Serialize};
use std::{
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

static LOCAL_OPERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratePasswordOperation {
    #[serde(default = "new_local_operation_id")]
    pub operation_id: String,
    pub request: ParanoidRequest,
    pub audit: bool,
}

impl GeneratePasswordOperation {
    pub fn new(request: ParanoidRequest, audit: bool) -> Self {
        Self {
            operation_id: new_local_operation_id(),
            request,
            audit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratePasswordOutcome {
    pub operation_id: String,
    pub report: GenerationReport,
    pub audit_events: Vec<AuditEvent>,
}

impl GeneratePasswordOutcome {
    pub fn automation_report(&self) -> GeneratePasswordAutomationReport<'_> {
        GeneratePasswordAutomationReport {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation: "generate_password",
            operation_id: &self.operation_id,
            status: if report_pass(&self.report.audit) {
                "success"
            } else {
                "review"
            },
            report: &self.report,
            audit_events: &self.audit_events,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratePasswordAutomationReport<'a> {
    pub schema_version: u16,
    pub operation: &'static str,
    pub operation_id: &'a str,
    pub status: &'static str,
    pub report: &'a GenerationReport,
    pub audit_events: &'a [AuditEvent],
}

#[derive(Debug, Error)]
#[error("{source}")]
pub struct GeneratePasswordError {
    operation_id: String,
    source: ParanoidError,
    audit_events: Vec<AuditEvent>,
}

impl GeneratePasswordError {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn source(&self) -> &ParanoidError {
        &self.source
    }

    pub fn audit_events(&self) -> &[AuditEvent] {
        &self.audit_events
    }

    pub fn failure_report(&self) -> GeneratePasswordFailureReport<'_> {
        GeneratePasswordFailureReport {
            schema_version: AUDIT_SCHEMA_VERSION,
            operation: "generate_password",
            operation_id: &self.operation_id,
            status: "error",
            error_kind: paranoid_error_kind(&self.source),
            error_message: self.source.to_string(),
            audit_events: &self.audit_events,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratePasswordFailureReport<'a> {
    pub schema_version: u16,
    pub operation: &'static str,
    pub operation_id: &'a str,
    pub status: &'static str,
    pub error_kind: &'static str,
    pub error_message: String,
    pub audit_events: &'a [AuditEvent],
}

pub fn run_generate_password_operation(
    operation: GeneratePasswordOperation,
) -> Result<GeneratePasswordOutcome, GeneratePasswordError> {
    let mut trail = AuditTrail::for_operation(operation.operation_id);
    trail.record(
        AuditSurface::Ops,
        AuditSubject::PasswordGeneration,
        "generate_password.start",
        AuditOutcome::Started,
        AuditSeverity::Info,
        "password generation operation started",
    );

    let result = paranoid_core::execute_request(&operation.request, operation.audit, |stage| {
        record_stage(&mut trail, stage);
    });

    match result {
        Ok(report) => {
            let outcome = if report_pass(&report.audit) {
                AuditOutcome::Success
            } else {
                AuditOutcome::Review
            };
            let severity = if outcome == AuditOutcome::Review {
                AuditSeverity::Warning
            } else {
                AuditSeverity::Notice
            };
            trail
                .record(
                    AuditSurface::Ops,
                    AuditSubject::PasswordGeneration,
                    "generate_password.complete",
                    outcome,
                    severity,
                    "password generation operation completed",
                )
                .attributes
                .insert(
                    "password_count".to_string(),
                    report.passwords.len().to_string(),
                );
            Ok(GeneratePasswordOutcome {
                operation_id: trail.operation_id().to_string(),
                report,
                audit_events: trail.into_events(),
            })
        }
        Err(source) => {
            let operation_id = trail.operation_id().to_string();
            trail.record(
                AuditSurface::Ops,
                AuditSubject::PasswordGeneration,
                "generate_password.error",
                AuditOutcome::Failure,
                AuditSeverity::Error,
                source.to_string(),
            );
            Err(GeneratePasswordError {
                operation_id,
                source,
                audit_events: trail.into_events(),
            })
        }
    }
}

fn report_pass(audit: &Option<AuditSummary>) -> bool {
    match audit {
        Some(audit) => audit.overall_pass,
        None => true,
    }
}

pub fn new_local_operation_id() -> String {
    let sequence = LOCAL_OPERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let time_component = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos().to_string(),
        Err(error) => format!("pre_epoch_{}", error.duration().as_nanos()),
    };
    format!(
        "pp.operation.v1.{}.{}.{}",
        process::id(),
        time_component,
        sequence
    )
}

fn record_stage(trail: &mut AuditTrail, stage: AuditStage) {
    trail
        .record(
            AuditSurface::Core,
            AuditSubject::StatisticalAudit,
            format!("audit_stage.{}", audit_stage_id(stage)),
            AuditOutcome::Success,
            AuditSeverity::Info,
            stage.label(),
        )
        .attributes
        .insert("stage".to_string(), audit_stage_id(stage).to_string());
}

fn audit_stage_id(stage: AuditStage) -> &'static str {
    match stage {
        AuditStage::Generate => "generate",
        AuditStage::ChiSquared => "chi_squared",
        AuditStage::SerialCorrelation => "serial_correlation",
        AuditStage::CollisionDetection => "collision_detection",
        AuditStage::EntropyProofs => "entropy_proofs",
        AuditStage::PatternDetection => "pattern_detection",
        AuditStage::ThreatAssessment => "threat_assessment",
        AuditStage::Complete => "complete",
    }
}

fn paranoid_error_kind(error: &ParanoidError) -> &'static str {
    match error {
        ParanoidError::InvalidArguments(_) => "invalid_arguments",
        ParanoidError::ImpossibleRequirements(_) => "impossible_requirements",
        ParanoidError::RandomFailure(_) => "random_failure",
        ParanoidError::HashFailure(_) => "hash_failure",
        ParanoidError::ExhaustedAttempts => "exhausted_attempts",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paranoid_core::{CharRequirements, CharsetSpec};

    #[test]
    fn generate_operation_records_core_audit_stages_without_secret_values() {
        let outcome = run_generate_password_operation(GeneratePasswordOperation {
            operation_id: "pp.operation.v1.test-success".to_string(),
            request: ParanoidRequest {
                length: 12,
                count: 1,
                batch_size: 12,
                charset: CharsetSpec::NamedOrLiteral("hex".to_string()),
                requirements: CharRequirements::default(),
                selected_frameworks: Vec::new(),
            },
            audit: true,
        })
        .expect("operation succeeds");

        assert_eq!(outcome.operation_id, "pp.operation.v1.test-success");
        assert_eq!(outcome.report.passwords.len(), 1);
        assert!(
            outcome
                .audit_events
                .iter()
                .any(|event| event.action == "audit_stage.chi_squared")
        );
        let generated = outcome.report.passwords[0].value.as_str();
        assert!(
            !outcome
                .audit_events
                .iter()
                .any(|event| event.message.contains(generated))
        );
        assert!(
            outcome
                .audit_events
                .iter()
                .all(|event| event.operation_id == outcome.operation_id)
        );
    }

    #[test]
    fn generate_operation_failure_keeps_audit_events_for_automation() {
        let error = run_generate_password_operation(GeneratePasswordOperation {
            operation_id: "pp.operation.v1.test-failure".to_string(),
            request: ParanoidRequest {
                length: 0,
                ..ParanoidRequest::default()
            },
            audit: true,
        })
        .expect_err("invalid request fails");

        assert_eq!(error.failure_report().error_kind, "invalid_arguments");
        assert_eq!(error.operation_id(), "pp.operation.v1.test-failure");
        assert_eq!(
            error.failure_report().operation_id,
            "pp.operation.v1.test-failure"
        );
        assert!(!error.audit_events().is_empty());
    }

    #[test]
    fn local_operation_ids_are_process_local_non_secret_identifiers() {
        let first = new_local_operation_id();
        let second = new_local_operation_id();

        assert!(first.starts_with("pp.operation.v1."));
        assert!(second.starts_with("pp.operation.v1."));
        assert_ne!(first, second);
    }
}
