//! TLS certificate pinning (SHA-256 of the leaf certificate DER).
//!
//! Operators set `WEISSMAN_AGENT_TLS_PIN_SHA256` to one or more hex digests
//! (`openssl x509 -in server.crt -outform DER | sha256sum`). HTTPS without a pin
//! is refused unless `WEISSMAN_AGENT_ALLOW_UNPINNED=1`.

use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

#[must_use]
pub fn pins_from_env() -> Vec<String> {
    std::env::var("WEISSMAN_AGENT_TLS_PIN_SHA256")
        .ok()
        .unwrap_or_default()
        .split([',', ' ', '\n'])
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .map(|s| s.strip_prefix("sha256/").unwrap_or(&s).replace(':', ""))
        .collect()
}

#[must_use]
pub fn allow_unpinned() -> bool {
    matches!(
        std::env::var("WEISSMAN_AGENT_ALLOW_UNPINNED").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

#[must_use]
pub fn pin_required_for_url(server_url: &str) -> bool {
    let https =
        server_url.trim().starts_with("https://") || server_url.trim().starts_with("wss://");
    https && !allow_unpinned()
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn pin_matches(leaf_der: &[u8], pins: &[String]) -> bool {
    let got = sha256_hex(leaf_der);
    pins.iter().any(|p| p.eq_ignore_ascii_case(&got))
}

/// Fail closed before opening a socket when HTTPS is used without a pin.
pub fn require_pin_or_dev(server_url: &str) -> anyhow::Result<Vec<String>> {
    let pins = pins_from_env();
    if !pins.is_empty() {
        return Ok(pins);
    }
    if pin_required_for_url(server_url) {
        anyhow::bail!(
            "WEISSMAN_AGENT_TLS_PIN_SHA256 is required for HTTPS (set WEISSMAN_AGENT_ALLOW_UNPINNED=1 only in lab)"
        );
    }
    Ok(pins)
}

/// rustls ClientConfig that accepts only a pinned leaf certificate.
///
/// Handshake signatures are still verified against that leaf so an attacker
/// cannot present the pinned public cert with a different keypair.
pub fn pinned_client_config(pins: Vec<String>) -> anyhow::Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let verifier = Arc::new(PinVerifier { pins });
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// HTTP client that pins the leaf when pins are configured.
pub fn http_client(server_url: &str, timeout: Duration) -> anyhow::Result<reqwest::Client> {
    let pins = require_pin_or_dev(server_url)?;
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if pins.is_empty() {
        builder = builder.use_rustls_tls();
    } else {
        let cfg = pinned_client_config(pins)?;
        builder = builder.use_preconfigured_tls(cfg);
    }
    Ok(builder.build()?)
}

#[derive(Debug)]
struct PinVerifier {
    pins: Vec<String>,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if pin_matches(end_entity.as_ref(), &self.pins) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "tls pin mismatch (got {})",
                sha256_hex(end_entity.as_ref())
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pins() {
        std::env::set_var("WEISSMAN_AGENT_TLS_PIN_SHA256", "SHA256/Ab:cd, deadbeef");
        let pins = pins_from_env();
        assert!(pins.iter().any(|p| p == "abcd"));
        assert!(pins.iter().any(|p| p == "deadbeef"));
        std::env::remove_var("WEISSMAN_AGENT_TLS_PIN_SHA256");
    }

    #[test]
    fn pin_match_is_exact() {
        let der = b"leaf-cert-bytes";
        let hex = sha256_hex(der);
        assert!(pin_matches(der, &[hex.clone()]));
        assert!(!pin_matches(der, &["00".repeat(32)]));
    }

    #[test]
    fn https_without_pin_is_refused() {
        std::env::remove_var("WEISSMAN_AGENT_TLS_PIN_SHA256");
        std::env::remove_var("WEISSMAN_AGENT_ALLOW_UNPINNED");
        assert!(require_pin_or_dev("https://api.example").is_err());
        assert!(require_pin_or_dev("http://127.0.0.1:8000").is_ok());
    }
}
