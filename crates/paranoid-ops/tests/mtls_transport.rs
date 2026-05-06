use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509Name,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use paranoid_audit::AuditSurface;
use paranoid_ops::{
    FederalApprovedMode, FederalCryptoProviderEvidence, OPS_SCHEMA_VERSION, OpsActor, OpsActorKind,
    OpsCommand, OpsCommandEnvelope, OpsMtlsClientConfig, OpsMtlsServerConfig, OpsPolicyContext,
    OpsPolicyDecision, OpsProfile, OpsSession, OpsTransport, OpsTransportEvidence,
    VaultOperationAccess, handle_mtls_ops_command_stream, send_ops_command_over_mtls,
};
use std::{net::TcpListener, path::PathBuf, thread, time::Duration};

#[test]
fn mtls_jsonl_transport_evaluates_command_with_observed_peer_evidence() {
    let material = TestMtlsMaterial::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mTLS ops listener");
    let endpoint = format!("mtls://{}", listener.local_addr().expect("listener addr"));
    let server_config = material.server_config();
    let server_context = federal_context(true, true);
    let server = thread::spawn(move || {
        let (stream, _addr) = listener.accept().expect("accept mTLS ops command");
        handle_mtls_ops_command_stream(stream, &server_config, &server_context)
            .expect("handle mTLS ops command")
    });

    let envelope = OpsCommandEnvelope {
        schema_version: OPS_SCHEMA_VERSION,
        request_id: "pp.test.request.mtls.transport.export".to_string(),
        operation_id: "pp.test.operation.mtls.transport.export".to_string(),
        profile: OpsProfile::FederalReady,
        actor: OpsActor {
            actor_id: "external_assessor".to_string(),
            kind: OpsActorKind::ServiceAccount,
        },
        session: OpsSession {
            session_id: "pp.test.session.mtls.transport.export".to_string(),
            surface: AuditSurface::Gui,
            transport: OpsTransport::InProcess,
            transport_evidence: Some(OpsTransportEvidence::unauthenticated_mtls(
                "client-claimed-identity",
                "client-claimed-evidence",
                "client supplied evidence must be replaced by server-observed mTLS evidence",
            )),
        },
        command: OpsCommand::VaultOperation {
            name: "export".to_string(),
            access: VaultOperationAccess::Export,
        },
    };
    let client_config = material
        .client_config(endpoint)
        .with_timeout(Duration::from_secs(5));

    let client_trace =
        send_ops_command_over_mtls(&client_config, envelope).expect("client receives trace");
    let server_trace = server.join().expect("server joins");

    assert_eq!(client_trace, server_trace);
    assert!(matches!(
        client_trace.decision,
        OpsPolicyDecision::Allow { .. }
    ));
    assert_eq!(client_trace.envelope.session.surface, AuditSurface::Gui);
    assert_eq!(client_trace.envelope.session.transport, OpsTransport::Mtls);
    let evidence = client_trace
        .envelope
        .session
        .transport_evidence
        .as_ref()
        .expect("server-observed transport evidence");
    assert!(evidence.authenticated);
    assert_eq!(evidence.evidence_source, "openssl-mtls-jsonl-v1");
    assert!(evidence.peer_identity.contains("CN=127.0.0.1"));
    assert_eq!(
        evidence
            .certificate_fingerprint_sha256
            .as_deref()
            .unwrap_or_default()
            .len(),
        64
    );
    assert_ne!(evidence.peer_identity, "client-claimed-identity");
    assert!(client_trace.audit_events.iter().all(|event| {
        event
            .attributes
            .get("session_transport")
            .is_some_and(|transport| transport == "mtls")
    }));
    assert!(client_trace.audit_events.iter().all(|event| {
        event
            .attributes
            .get("transport_evidence_source")
            .is_some_and(|source| source == "openssl-mtls-jsonl-v1")
    }));
    assert!(!client_trace.audit_events.iter().any(|event| {
        event
            .attributes
            .keys()
            .any(|attribute| attribute.contains("private_key") || attribute.contains("secret"))
    }));
}

#[test]
fn mtls_jsonl_transport_rejects_untrusted_client_certificate() {
    let server_material = TestMtlsMaterial::new();
    let untrusted_client_material = TestMtlsMaterial::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mTLS ops listener");
    let endpoint = format!("mtls://{}", listener.local_addr().expect("listener addr"));
    let server_config = server_material.server_config();
    let server_context = federal_context(true, true);
    let server = thread::spawn(move || {
        let (stream, _addr) = listener.accept().expect("accept mTLS ops command");
        handle_mtls_ops_command_stream(stream, &server_config, &server_context)
    });

    let envelope = OpsCommandEnvelope {
        schema_version: OPS_SCHEMA_VERSION,
        request_id: "pp.test.request.mtls.transport.untrusted".to_string(),
        operation_id: "pp.test.operation.mtls.transport.untrusted".to_string(),
        profile: OpsProfile::FederalReady,
        actor: OpsActor::default(),
        session: OpsSession {
            session_id: "pp.test.session.mtls.transport.untrusted".to_string(),
            surface: AuditSurface::Ops,
            transport: OpsTransport::Mtls,
            transport_evidence: None,
        },
        command: OpsCommand::VaultOperation {
            name: "export".to_string(),
            access: VaultOperationAccess::Export,
        },
    };
    let client_config = OpsMtlsClientConfig::new(
        endpoint,
        untrusted_client_material.cert_path.clone(),
        untrusted_client_material.key_path.clone(),
        server_material.ca_path.clone(),
    )
    .with_timeout(Duration::from_secs(5));

    let client_error = send_ops_command_over_mtls(&client_config, envelope)
        .expect_err("untrusted client certificate fails closed");
    let server_error = server
        .join()
        .expect("server joins")
        .expect_err("server rejects untrusted client certificate");

    assert!(
        client_error
            .to_string()
            .contains("mTLS command transport failed")
    );
    assert!(server_error.to_string().contains("handshake"));
}

fn federal_context(audit_sink_required: bool, audit_sink_available: bool) -> OpsPolicyContext {
    OpsPolicyContext {
        profile: OpsProfile::FederalReady,
        audit_sink_required,
        audit_sink_available,
        crypto_provider: FederalCryptoProviderEvidence {
            provider_name: "OpenSSL".to_string(),
            provider_version: "OpenSSL fixture provider".to_string(),
            provider_platform: "fixture-platform".to_string(),
            approved_mode: FederalApprovedMode::Confirmed,
            certificate_reference: Some("CMVP fixture certificate".to_string()),
            evidence_source: "fixture".to_string(),
        },
        seal_posture: None,
    }
}

struct TestMtlsMaterial {
    _dir: tempfile::TempDir,
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_path: PathBuf,
}

impl TestMtlsMaterial {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = test_key();
        let cert = test_certificate(&key);
        let cert_path = dir.path().join("ops-client.crt");
        let key_path = dir.path().join("ops-client.key");
        let ca_path = dir.path().join("ops-ca.crt");
        std::fs::write(&cert_path, cert.to_pem().expect("cert pem")).expect("write cert");
        std::fs::write(&ca_path, cert.to_pem().expect("ca pem")).expect("write ca");
        std::fs::write(
            &key_path,
            key.private_key_to_pem_pkcs8().expect("private key pem"),
        )
        .expect("write key");
        Self {
            _dir: dir,
            cert_path,
            key_path,
            ca_path,
        }
    }

    fn server_config(&self) -> OpsMtlsServerConfig {
        OpsMtlsServerConfig::new(
            self.cert_path.clone(),
            self.key_path.clone(),
            self.ca_path.clone(),
        )
    }

    fn client_config(&self, endpoint: String) -> OpsMtlsClientConfig {
        OpsMtlsClientConfig::new(
            endpoint,
            self.cert_path.clone(),
            self.key_path.clone(),
            self.ca_path.clone(),
        )
    }
}

fn test_key() -> PKey<Private> {
    let rsa = Rsa::generate(2048).expect("rsa");
    PKey::from_rsa(rsa).expect("pkey")
}

fn test_certificate(key: &PKey<Private>) -> X509 {
    let mut name = X509Name::builder().expect("x509 name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "127.0.0.1")
        .expect("common name");
    let name = name.build();

    let mut serial = BigNum::new().expect("serial");
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .expect("rand serial");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("unix epoch")
        .as_secs() as i64;
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("set version");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("asn1 serial"))
        .expect("set serial");
    builder.set_subject_name(&name).expect("set subject");
    builder.set_issuer_name(&name).expect("set issuer");
    builder
        .set_not_before(&Asn1Time::from_unix(now - 60).expect("not before"))
        .expect("apply not before");
    builder
        .set_not_after(&Asn1Time::from_unix(now + 86_400).expect("not after"))
        .expect("apply not after");
    builder.set_pubkey(key).expect("set pubkey");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("basic constraints"),
        )
        .expect("append basic constraints");
    builder
        .append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .key_cert_sign()
                .build()
                .expect("key usage"),
        )
        .expect("append key usage");
    builder
        .append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()
                .expect("extended key usage"),
        )
        .expect("append extended key usage");
    let san = {
        let context = builder.x509v3_context(None, None);
        SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&context)
            .expect("subject alt name")
    };
    builder
        .append_extension(san)
        .expect("append subject alt name");
    builder
        .sign(key, MessageDigest::sha256())
        .expect("sign cert");
    builder.build()
}
