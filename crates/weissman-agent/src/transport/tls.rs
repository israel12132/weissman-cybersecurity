//! TLS for enrollment HTTPS + agent WSS.
//!
//! Trust store = webpki public roots ∪ the host native store (so enterprise
//! SSL inspection CAs work). Optional hard pin via `WEISSMAN_SERVER_CERT_SHA256`.
//! Otherwise TOFU: first successful verify records the leaf SHA-256; later
//! handshakes accept a matching pin or a roots-trusted rotation (Let's Encrypt
//! / inspection-cert rollover).

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

static TOFU_PIN: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static OBSERVED_PIN: Mutex<Option<[u8; 32]>> = Mutex::new(None);
static PIN_CHANGED: AtomicBool = AtomicBool::new(false);

/// Load a previously persisted TOFU pin (64 hex chars).
pub fn set_tofu_pin_hex(hex_pin: &str) {
    if let Some(p) = parse_pin(hex_pin) {
        if let Ok(mut g) = TOFU_PIN.lock() {
            *g = Some(p);
        }
    }
}

/// Hex SHA-256 of the leaf we last accepted (for persistence).
#[must_use]
pub fn observed_pin_hex() -> Option<String> {
    OBSERVED_PIN.lock().ok().and_then(|g| g.map(hex::encode))
}

#[must_use]
pub fn pin_changed() -> bool {
    PIN_CHANGED.swap(false, Ordering::Relaxed)
}

fn parse_pin(s: &str) -> Option<[u8; 32]> {
    let t = s.trim();
    let bytes = hex::decode(t).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Some(a)
}

fn leaf_sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    let d = Sha256::digest(cert.as_ref());
    let mut a = [0u8; 32];
    a.copy_from_slice(&d);
    a
}

fn combined_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // rustls-native-certs 0.8 returns CertificateResult (certs + per-cert errors),
    // not Result. Enterprise SSL-inspection CAs live in this store.
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        tracing::debug!(
            target: "agent",
            errors = native.errors.len(),
            "some native TLS roots were skipped"
        );
    }
    for c in native.certs {
        let _ = roots.add(c);
    }
    roots
}

#[derive(Debug)]
struct WeissmanVerifier {
    inner: Arc<WebPkiServerVerifier>,
    hard_pin: Option<[u8; 32]>,
}

impl ServerCertVerifier for WeissmanVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let hash = leaf_sha256(end_entity);
        if let Some(pin) = self.hard_pin {
            if hash == pin {
                if let Ok(mut g) = OBSERVED_PIN.lock() {
                    *g = Some(hash);
                }
                return Ok(ServerCertVerified::assertion());
            }
            return Err(TlsError::General(
                "server certificate does not match WEISSMAN_SERVER_CERT_SHA256 pin".into(),
            ));
        }
        let tofu = TOFU_PIN.lock().ok().and_then(|g| *g);
        if let Some(pin) = tofu {
            if hash == pin {
                if let Ok(mut g) = OBSERVED_PIN.lock() {
                    *g = Some(hash);
                }
                return Ok(ServerCertVerified::assertion());
            }
        }
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => {
                if tofu.is_some() && tofu != Some(hash) {
                    PIN_CHANGED.store(true, Ordering::Relaxed);
                    tracing::info!(
                        target: "agent",
                        "TLS leaf rotated under a trusted CA; updating TOFU pin"
                    );
                }
                if let Ok(mut g) = OBSERVED_PIN.lock() {
                    *g = Some(hash);
                }
                if let Ok(mut g) = TOFU_PIN.lock() {
                    *g = Some(hash);
                }
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// rustls client config: webpki ∪ native roots, plus pinning.
pub fn rustls_client_config() -> anyhow::Result<ClientConfig> {
    install_crypto_provider();
    let roots = combined_roots();
    if roots.is_empty() {
        anyhow::bail!("TLS root store is empty (webpki + native)");
    }
    let inner = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow::anyhow!("web pki verifier: {e}"))?;
    let hard_pin = std::env::var("WEISSMAN_SERVER_CERT_SHA256")
        .ok()
        .as_deref()
        .and_then(parse_pin);
    let verifier = Arc::new(WeissmanVerifier { inner, hard_pin });
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(cfg)
}

/// Persist the last accepted leaf SHA-256 onto `agent.state` (TOFU).
pub fn persist_observed_pin() {
    let Some(hex) = observed_pin_hex() else {
        return;
    };
    let path = super::state::state_path();
    if let Some(mut s) = super::state::load(&path) {
        if s.server_cert_sha256 != hex {
            s.server_cert_sha256 = hex;
            let _ = super::state::save(&path, &s);
        }
    }
}

pub fn reqwest_client(
    timeout: std::time::Duration,
    user_agent: &str,
) -> anyhow::Result<reqwest::Client> {
    let cfg = rustls_client_config()?;
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(user_agent)
        .use_preconfigured_tls(cfg)
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pin_rejects_short() {
        assert!(parse_pin("abcd").is_none());
        assert!(parse_pin(&"ab".repeat(32)).is_some());
    }

    #[test]
    fn rustls_config_unions_webpki_roots() {
        let cfg = rustls_client_config();
        assert!(cfg.is_ok(), "webpki roots must populate the store: {cfg:?}");
    }
}
