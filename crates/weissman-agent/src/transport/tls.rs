//! TLS for enrollment HTTPS + agent WSS.
//!
//! The Weissman gateway is pin-first. `WEISSMAN_SERVER_CERT_SHA256` (or a
//! previously persisted leaf pin) is the only acceptable handshake. A matching
//! pin is accepted; a mismatch is rejected **without** falling through to the
//! OS trust store — that is how SSL-inspection MITM is blocked.
//! First-boot bootstrap (no pin yet) verifies against **webpki public roots
//! only**, then freezes the leaf SHA-256 as a sticky pin. Native CAs are never
//! used to accept the sovereign gateway.

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

/// Load a previously persisted TOFU pin (64 hex chars). After this the pin is sticky.
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

fn public_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct NativeCertStats {
    added: usize,
    skipped_parse: usize,
    load_errors: usize,
}

/// Fault-tolerant parse of the host store (junk CAs skipped). Not used to
/// accept the Weissman gateway — kept so a future non-gateway client can
/// merge enterprise CAs without aborting on SHA-1/expired internals.
fn absorb_native_certs(roots: &mut RootCertStore) -> NativeCertStats {
    let native = rustls_native_certs::load_native_certs();
    let load_errors = native.errors.len();
    let (added, skipped_parse) = roots.add_parsable_certificates(native.certs);
    NativeCertStats {
        added,
        skipped_parse,
        load_errors,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayTrust {
    AcceptPinned,
    RejectPinMismatch,
    BootstrapPublicRoots,
}

/// Pin is exclusive. A known pin never falls through to any CA, native or public.
#[must_use]
pub(crate) fn gateway_trust(
    env_pin: Option<[u8; 32]>,
    sticky: Option<[u8; 32]>,
    leaf: [u8; 32],
) -> GatewayTrust {
    if let Some(pin) = env_pin.or(sticky) {
        if pin == leaf {
            GatewayTrust::AcceptPinned
        } else {
            GatewayTrust::RejectPinMismatch
        }
    } else {
        GatewayTrust::BootstrapPublicRoots
    }
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
        let sticky = TOFU_PIN.lock().ok().and_then(|g| *g);
        match gateway_trust(self.hard_pin, sticky, hash) {
            GatewayTrust::AcceptPinned => {
                if let Ok(mut g) = OBSERVED_PIN.lock() {
                    *g = Some(hash);
                }
                return Ok(ServerCertVerified::assertion());
            }
            GatewayTrust::RejectPinMismatch => {
                return Err(TlsError::General(
                    "server certificate does not match the pinned Weissman gateway SHA-256 \
                     (OS trust store is not a fallback — SSL interception blocked)"
                        .into(),
                ));
            }
            GatewayTrust::BootstrapPublicRoots => {}
        }
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => {
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

/// rustls client config: webpki public roots for bootstrap; pin is exclusive.
pub fn rustls_client_config() -> anyhow::Result<ClientConfig> {
    install_crypto_provider();
    let roots = public_roots();
    if roots.is_empty() {
        anyhow::bail!("TLS root store is empty (webpki public roots)");
    }
    {
        let mut discarded = RootCertStore::empty();
        let stats = absorb_native_certs(&mut discarded);
        if stats.added + stats.skipped_parse + stats.load_errors > 0 {
            tracing::debug!(
                target: "agent",
                parsed = stats.added,
                skipped_parse = stats.skipped_parse,
                load_errors = stats.load_errors,
                "native CAs parsed with fault-tolerant skip; not trusted for Weissman gateway"
            );
        }
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

/// Persist the last accepted leaf SHA-256 onto `agent.state` (sticky pin).
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

    #[test]
    fn garbage_native_cert_is_skipped_not_fatal() {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let before = roots.len();
        let garbage = vec![
            CertificateDer::from(vec![0x30, 0x00, 0xff, 0x00]),
            CertificateDer::from(vec![0u8; 8]),
            CertificateDer::from(b"not-a-certificate".to_vec()),
        ];
        let (added, skipped) = roots.add_parsable_certificates(garbage);
        assert_eq!(added, 0);
        assert_eq!(skipped, 3);
        assert_eq!(roots.len(), before, "webpki roots must survive junk CAs");
        let _ = absorb_native_certs(&mut roots);
        assert!(!public_roots().is_empty());
    }

    #[test]
    fn public_roots_never_empty() {
        assert!(!public_roots().is_empty());
    }

    #[test]
    fn pinned_leaf_never_falls_through_to_os_store() {
        let pin = [0x11u8; 32];
        let other = [0x22u8; 32];
        assert_eq!(
            gateway_trust(Some(pin), None, pin),
            GatewayTrust::AcceptPinned
        );
        assert_eq!(
            gateway_trust(Some(pin), None, other),
            GatewayTrust::RejectPinMismatch
        );
        assert_eq!(
            gateway_trust(None, Some(pin), other),
            GatewayTrust::RejectPinMismatch
        );
        assert_eq!(
            gateway_trust(None, None, other),
            GatewayTrust::BootstrapPublicRoots
        );
    }
}
