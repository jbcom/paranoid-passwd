use crate::{
    OPS_SCHEMA_VERSION, OpsCommandEnvelope, OpsCommandTrace, OpsPolicyContext, OpsSession,
    OpsTransportEvidence, evaluate_ops_command_envelope,
};
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509VerifyResult},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

pub const OPS_MTLS_JSONL_TRANSPORT_SCHEMA_VERSION: u16 = 1;
pub const OPS_MTLS_JSONL_MAX_LINE_BYTES: usize = 1024 * 1024;
const OPS_MTLS_EVIDENCE_SOURCE: &str = "openssl-mtls-jsonl-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsMtlsClientConfig {
    pub endpoint: String,
    pub client_certificate_path: PathBuf,
    pub client_private_key_path: PathBuf,
    pub ca_certificate_path: PathBuf,
    pub timeout: Duration,
}

impl OpsMtlsClientConfig {
    pub fn new(
        endpoint: impl Into<String>,
        client_certificate_path: impl Into<PathBuf>,
        client_private_key_path: impl Into<PathBuf>,
        ca_certificate_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            client_certificate_path: client_certificate_path.into(),
            client_private_key_path: client_private_key_path.into(),
            ca_certificate_path: ca_certificate_path.into(),
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsMtlsServerConfig {
    pub server_certificate_path: PathBuf,
    pub server_private_key_path: PathBuf,
    pub client_ca_certificate_path: PathBuf,
    pub timeout: Duration,
}

impl OpsMtlsServerConfig {
    pub fn new(
        server_certificate_path: impl Into<PathBuf>,
        server_private_key_path: impl Into<PathBuf>,
        client_ca_certificate_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            server_certificate_path: server_certificate_path.into(),
            server_private_key_path: server_private_key_path.into(),
            client_ca_certificate_path: client_ca_certificate_path.into(),
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsMtlsCommandRequest {
    pub schema_version: u16,
    pub envelope: OpsCommandEnvelope,
}

impl OpsMtlsCommandRequest {
    pub fn new(envelope: OpsCommandEnvelope) -> Self {
        Self {
            schema_version: OPS_MTLS_JSONL_TRANSPORT_SCHEMA_VERSION,
            envelope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsMtlsCommandResponse {
    pub schema_version: u16,
    pub trace: OpsCommandTrace,
}

#[derive(Debug, Error)]
pub enum OpsMtlsTransportError {
    #[error("invalid mTLS endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("mTLS configuration failure: {0}")]
    TlsConfig(String),
    #[error("mTLS handshake failure: {0}")]
    TlsHandshake(String),
    #[error("mTLS peer verification failed: {0}")]
    PeerVerification(String),
    #[error("mTLS protocol error: {0}")]
    Protocol(String),
    #[error("mTLS transport io failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("mTLS transport JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn send_ops_command_over_mtls(
    config: &OpsMtlsClientConfig,
    envelope: OpsCommandEnvelope,
) -> Result<OpsCommandTrace, OpsMtlsTransportError> {
    OpsMtlsClient::from_config(config)?.send(envelope)
}

pub fn handle_mtls_ops_command_stream(
    tcp_stream: TcpStream,
    config: &OpsMtlsServerConfig,
    context: &OpsPolicyContext,
) -> Result<OpsCommandTrace, OpsMtlsTransportError> {
    OpsMtlsServer::from_config(config)?.handle_stream(tcp_stream, context)
}

pub struct OpsMtlsClient {
    host: String,
    addresses: Vec<SocketAddr>,
    timeout: Duration,
    connector: SslConnector,
}

impl OpsMtlsClient {
    pub fn from_config(config: &OpsMtlsClientConfig) -> Result<Self, OpsMtlsTransportError> {
        Ok(Self {
            host: endpoint_host(config.endpoint.as_str())?,
            addresses: socket_addresses_from_endpoint(config.endpoint.as_str())?,
            timeout: config.timeout,
            connector: build_mtls_connector(
                &config.client_certificate_path,
                &config.client_private_key_path,
                &config.ca_certificate_path,
            )?,
        })
    }

    pub fn send(
        &self,
        envelope: OpsCommandEnvelope,
    ) -> Result<OpsCommandTrace, OpsMtlsTransportError> {
        let request = OpsMtlsCommandRequest::new(envelope);
        let mut request_line = serde_json::to_vec(&request)?;
        request_line.push(b'\n');

        let mut failures = Vec::new();
        for address in &self.addresses {
            let tcp_stream = match TcpStream::connect_timeout(address, self.timeout) {
                Ok(stream) => stream,
                Err(error) => {
                    failures.push(format!("{address}: tcp connect failed: {error}"));
                    continue;
                }
            };
            if let Err(error) = tcp_stream.set_read_timeout(Some(self.timeout)) {
                failures.push(format!("{address}: failed to set read timeout: {error}"));
                continue;
            }
            if let Err(error) = tcp_stream.set_write_timeout(Some(self.timeout)) {
                failures.push(format!("{address}: failed to set write timeout: {error}"));
                continue;
            }

            let mut tls_stream = match self.connector.connect(self.host.as_str(), tcp_stream) {
                Ok(stream) => stream,
                Err(error) => {
                    failures.push(format!("{address}: mTLS handshake failed: {error}"));
                    continue;
                }
            };
            if tls_stream.ssl().verify_result() != X509VerifyResult::OK {
                failures.push(format!(
                    "{address}: mTLS peer verification failed: {}",
                    tls_stream.ssl().verify_result()
                ));
                continue;
            }

            tls_stream.write_all(&request_line)?;
            tls_stream.flush()?;

            let mut reader = BufReader::new(tls_stream);
            let response_line = read_bounded_jsonl_line(
                &mut reader,
                "server closed mTLS command stream without a response",
                "mTLS command response exceeded maximum JSONL frame length",
            )?;
            let response: OpsMtlsCommandResponse = serde_json::from_str(response_line.trim())?;
            if response.schema_version != OPS_MTLS_JSONL_TRANSPORT_SCHEMA_VERSION {
                return Err(OpsMtlsTransportError::Protocol(format!(
                    "response schema mismatch: {}",
                    response.schema_version
                )));
            }
            return Ok(response.trace);
        }

        Err(OpsMtlsTransportError::TlsHandshake(format!(
            "mTLS command transport failed: {}",
            failures.join("; ")
        )))
    }
}

pub struct OpsMtlsServer {
    acceptor: SslAcceptor,
    timeout: Duration,
}

impl OpsMtlsServer {
    pub fn from_config(config: &OpsMtlsServerConfig) -> Result<Self, OpsMtlsTransportError> {
        Ok(Self {
            acceptor: build_mtls_acceptor(config)?,
            timeout: config.timeout,
        })
    }

    pub fn handle_stream(
        &self,
        tcp_stream: TcpStream,
        context: &OpsPolicyContext,
    ) -> Result<OpsCommandTrace, OpsMtlsTransportError> {
        tcp_stream.set_read_timeout(Some(self.timeout))?;
        tcp_stream.set_write_timeout(Some(self.timeout))?;
        let tls_stream = self
            .acceptor
            .accept(tcp_stream)
            .map_err(|error| OpsMtlsTransportError::TlsHandshake(error.to_string()))?;
        if tls_stream.ssl().verify_result() != X509VerifyResult::OK {
            return Err(OpsMtlsTransportError::PeerVerification(
                tls_stream.ssl().verify_result().to_string(),
            ));
        }
        let peer_certificate = tls_stream.ssl().peer_certificate().ok_or_else(|| {
            OpsMtlsTransportError::PeerVerification(
                "mTLS client certificate was not presented".to_string(),
            )
        })?;
        let transport_evidence = transport_evidence_from_peer_certificate(&peer_certificate)?;

        let mut reader = BufReader::new(tls_stream);
        let request_line = read_bounded_jsonl_line(
            &mut reader,
            "client closed mTLS command stream without a request",
            "mTLS command request exceeded maximum JSONL frame length",
        )?;
        let request: OpsMtlsCommandRequest = serde_json::from_str(request_line.trim())?;
        if request.schema_version != OPS_MTLS_JSONL_TRANSPORT_SCHEMA_VERSION {
            return Err(OpsMtlsTransportError::Protocol(format!(
                "request schema mismatch: {}",
                request.schema_version
            )));
        }
        if request.envelope.schema_version != OPS_SCHEMA_VERSION {
            return Err(OpsMtlsTransportError::Protocol(format!(
                "ops envelope schema mismatch: {}",
                request.envelope.schema_version
            )));
        }

        let mut envelope = request.envelope;
        let session_id = envelope.session.session_id.clone();
        let surface = envelope.session.surface;
        envelope.session = OpsSession::mtls(surface, session_id, transport_evidence);
        let trace = evaluate_ops_command_envelope(envelope, context).into_trace();
        let response = OpsMtlsCommandResponse {
            schema_version: OPS_MTLS_JSONL_TRANSPORT_SCHEMA_VERSION,
            trace: trace.clone(),
        };
        let mut response_line = serde_json::to_vec(&response)?;
        response_line.push(b'\n');
        let tls_stream = reader.get_mut();
        tls_stream.write_all(&response_line)?;
        tls_stream.flush()?;
        Ok(trace)
    }
}

fn transport_evidence_from_peer_certificate(
    certificate: &X509,
) -> Result<OpsTransportEvidence, OpsMtlsTransportError> {
    let fingerprint = certificate
        .digest(MessageDigest::sha256())
        .map_err(|error| OpsMtlsTransportError::TlsConfig(error.to_string()))?;
    Ok(OpsTransportEvidence::authenticated_mtls(
        certificate_subject(certificate),
        hex_encode(fingerprint.as_ref()),
        OPS_MTLS_EVIDENCE_SOURCE,
    ))
}

fn build_mtls_connector(
    certificate_path: &Path,
    private_key_path: &Path,
    ca_certificate_path: &Path,
) -> Result<SslConnector, OpsMtlsTransportError> {
    let connector: Result<SslConnector, ErrorStack> = (|| {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_certificate_file(certificate_path, SslFiletype::PEM)?;
        builder.set_private_key_file(private_key_path, SslFiletype::PEM)?;
        builder.set_ca_file(ca_certificate_path)?;
        builder.check_private_key()?;
        Ok(builder.build())
    })();
    connector.map_err(|error| OpsMtlsTransportError::TlsConfig(error.to_string()))
}

fn build_mtls_acceptor(config: &OpsMtlsServerConfig) -> Result<SslAcceptor, OpsMtlsTransportError> {
    let acceptor: Result<SslAcceptor, ErrorStack> = (|| {
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_certificate_file(&config.server_certificate_path, SslFiletype::PEM)?;
        builder.set_private_key_file(&config.server_private_key_path, SslFiletype::PEM)?;
        builder.set_ca_file(&config.client_ca_certificate_path)?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        builder.check_private_key()?;
        Ok(builder.build())
    })();
    acceptor.map_err(|error| OpsMtlsTransportError::TlsConfig(error.to_string()))
}

fn read_bounded_jsonl_line(
    reader: &mut impl BufRead,
    eof_message: &'static str,
    overrun_message: &'static str,
) -> Result<String, OpsMtlsTransportError> {
    let mut line = Vec::new();

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(OpsMtlsTransportError::Protocol(eof_message.to_string()));
        }

        if let Some(newline_index) = available.iter().position(|byte| *byte == b'\n') {
            let bytes_to_take = newline_index + 1;
            if line.len() + bytes_to_take > OPS_MTLS_JSONL_MAX_LINE_BYTES {
                return Err(OpsMtlsTransportError::Protocol(overrun_message.to_string()));
            }
            line.extend_from_slice(&available[..bytes_to_take]);
            reader.consume(bytes_to_take);
            break;
        }

        let remaining = OPS_MTLS_JSONL_MAX_LINE_BYTES.saturating_sub(line.len());
        if available.len() >= remaining {
            if remaining > 0 {
                line.extend_from_slice(&available[..remaining]);
                reader.consume(remaining);
            }
            return Err(OpsMtlsTransportError::Protocol(overrun_message.to_string()));
        }

        let bytes_to_take = available.len();
        line.extend_from_slice(available);
        reader.consume(bytes_to_take);
    }

    String::from_utf8(line).map_err(|error| {
        OpsMtlsTransportError::Protocol(format!("mTLS JSONL frame was not UTF-8: {error}"))
    })
}

fn socket_addresses_from_endpoint(
    endpoint: &str,
) -> Result<Vec<std::net::SocketAddr>, OpsMtlsTransportError> {
    let authority = endpoint_authority(endpoint)?;
    let addresses: Vec<std::net::SocketAddr> = authority
        .to_socket_addrs()
        .map_err(|error| OpsMtlsTransportError::InvalidEndpoint(format!("{endpoint:?}: {error}")))?
        .collect();
    if addresses.is_empty() {
        return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
            "{endpoint:?}: no socket addresses resolved"
        )));
    }
    Ok(addresses)
}

fn endpoint_host(endpoint: &str) -> Result<String, OpsMtlsTransportError> {
    let authority = endpoint_authority(endpoint)?;
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
                "{endpoint:?} must include [host]:port"
            )));
        };
        if host.is_empty() || port.is_empty() {
            return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
                "{endpoint:?} must include [host]:port"
            )));
        }
        return Ok(host.to_string());
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
            "{endpoint:?} must include host:port"
        )));
    };
    if host.is_empty() || port.is_empty() {
        return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
            "{endpoint:?} must include host:port"
        )));
    }
    Ok(host.to_string())
}

fn endpoint_authority(endpoint: &str) -> Result<String, OpsMtlsTransportError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(OpsMtlsTransportError::InvalidEndpoint(
            "endpoint is empty".to_string(),
        ));
    }
    let without_scheme = match trimmed.split_once("://") {
        Some((scheme, rest)) => match scheme {
            "mtls" | "tls" | "tcp" => rest,
            unsupported => {
                return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
                    "unsupported endpoint scheme: {unsupported}"
                )));
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
        return Err(OpsMtlsTransportError::InvalidEndpoint(format!(
            "{endpoint:?} must include host:port"
        )));
    }
    Ok(authority.to_string())
}

fn certificate_subject(certificate: &X509) -> String {
    let parts: Vec<String> = certificate
        .subject_name()
        .entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("unknown");
            let value = entry
                .data()
                .to_string()
                .unwrap_or_else(|_| "[non_utf8]".to_string());
            format!("{key}={value}")
        })
        .collect();
    if parts.is_empty() {
        "unknown_peer_certificate_subject".to_string()
    } else {
        parts.join(",")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const EOF_MESSAGE: &str = "eof";
    const OVERRUN_MESSAGE: &str = "overrun";

    #[test]
    fn bounded_jsonl_line_accepts_exact_maximum_frame_with_newline() {
        let mut frame = vec![b' '; OPS_MTLS_JSONL_MAX_LINE_BYTES - 1];
        frame.push(b'\n');
        let line = read_test_frame(frame).expect("maximum frame with newline is valid");

        assert_eq!(line.len(), OPS_MTLS_JSONL_MAX_LINE_BYTES);
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn bounded_jsonl_line_rejects_exact_maximum_frame_without_newline_as_overrun() {
        let error = read_test_frame(vec![b' '; OPS_MTLS_JSONL_MAX_LINE_BYTES])
            .expect_err("full frame without newline exceeds valid JSONL length");

        assert!(matches!(
            error,
            OpsMtlsTransportError::Protocol(message) if message == OVERRUN_MESSAGE
        ));
    }

    #[test]
    fn bounded_jsonl_line_rejects_more_than_maximum_frame_as_overrun() {
        let error = read_test_frame(vec![b' '; OPS_MTLS_JSONL_MAX_LINE_BYTES + 1])
            .expect_err("oversized frame fails closed");

        assert!(matches!(
            error,
            OpsMtlsTransportError::Protocol(message) if message == OVERRUN_MESSAGE
        ));
    }

    #[test]
    fn bounded_jsonl_line_reports_short_truncated_frame_as_eof() {
        let error = read_test_frame(b"{\"schema_version\":1".to_vec())
            .expect_err("short truncated frame is EOF, not overrun");

        assert!(matches!(
            error,
            OpsMtlsTransportError::Protocol(message) if message == EOF_MESSAGE
        ));
    }

    fn read_test_frame(frame: Vec<u8>) -> Result<String, OpsMtlsTransportError> {
        let mut reader = BufReader::new(Cursor::new(frame));
        read_bounded_jsonl_line(&mut reader, EOF_MESSAGE, OVERRUN_MESSAGE)
    }
}
