//! TLS for enrollment HTTPS + agent WSS.
//!
//! The Weissman gateway is pin-first. Active leaf pin(s)
//! (`WEISSMAN_SERVER_CERT_SHA256`, optional `_BACKUP` leaf, sticky TOFU) never
//! fall through to the OS store. A sovereign Root CA pin
//! (`WEISSMAN_SERVER_ROOT_CA_SHA256` and/or `WEISSMAN_SERVER_ROOT_CA_PEM`) is
//! the only rotation path: the presented chain must verify against that root,
//! then the new leaf is frozen. Leaf-hash == root-hash is NOT a valid check.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

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

fn parse_pin_list(s: &str) -> Vec<[u8; 32]> {
    s.split([',', ' ', '\n', '\t'])
        .filter_map(parse_pin)
        .collect()
}

fn pin_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

fn env_leaf_pins() -> Vec<[u8; 32]> {
    let mut pins = Vec::new();
    for key in [
        "WEISSMAN_SERVER_CERT_SHA256",
        "WEISSMAN_SERVER_CERT_SHA256_BACKUP",
    ] {
        if let Ok(v) = std::env::var(key) {
            pins.extend(parse_pin_list(&v));
        }
    }
    pins
}

fn env_root_ca_hash() -> Option<[u8; 32]> {
    std::env::var("WEISSMAN_SERVER_ROOT_CA_SHA256")
        .ok()
        .as_deref()
        .and_then(parse_pin)
}

fn env_root_ca_certs() -> Vec<CertificateDer<'static>> {
    let mut out = Vec::new();
    if let Ok(pem) = std::env::var("WEISSMAN_SERVER_ROOT_CA_PEM") {
        out.extend(pem_certs(&pem));
    }
    if let Ok(path) = std::env::var("WEISSMAN_SERVER_ROOT_CA_FILE") {
        if let Ok(pem) = std::fs::read_to_string(path) {
            out.extend(pem_certs(&pem));
        }
    }
    out
}

fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[start + 27..];
        let Some(end) = body.find("-----END CERTIFICATE-----") else {
            break;
        };
        let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64) {
            if !der.is_empty() {
                out.push(CertificateDer::from(der));
            }
        }
        rest = &body[end + 25..];
    }
    out
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
    TrySovereignRoot,
    RejectPinMismatch,
    BootstrapPublicRoots,
}

/// Pin is exclusive. OS store is never a fallback.
/// `backup_root` is a sovereign Root CA pin / PEM — used only to verify the
/// presented chain (rotation), never compared to the leaf hash.
#[must_use]
pub(crate) fn gateway_trust(
    leaf_pins: &[[u8; 32]],
    sticky: Option<[u8; 32]>,
    leaf: [u8; 32],
    backup_root: bool,
) -> GatewayTrust {
    let mut pins: Vec<[u8; 32]> = leaf_pins.to_vec();
    if let Some(s) = sticky {
        if !pins.iter().any(|p| pin_eq(p, &s)) {
            pins.push(s);
        }
    }
    if pins.is_empty() {
        return GatewayTrust::BootstrapPublicRoots;
    }
    if pins.iter().any(|p| pin_eq(p, &leaf)) {
        return GatewayTrust::AcceptPinned;
    }
    if backup_root {
        GatewayTrust::TrySovereignRoot
    } else {
        GatewayTrust::RejectPinMismatch
    }
}

#[derive(Debug)]
struct WeissmanVerifier {
    inner: Arc<WebPkiServerVerifier>,
    leaf_pins: Vec<[u8; 32]>,
    root_ca_hash: Option<[u8; 32]>,
    root_ca_certs: Vec<CertificateDer<'static>>,
}

impl WeissmanVerifier {
    fn backup_configured(&self) -> bool {
        self.root_ca_hash.is_some() || !self.root_ca_certs.is_empty()
    }

    fn verify_sovereign_root(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let mut roots = RootCertStore::empty();
        for c in &self.root_ca_certs {
            let _ = roots.add(c.clone());
        }
        let mut presented: Vec<CertificateDer<'static>> = Vec::new();
        presented.push(CertificateDer::from(end_entity.as_ref().to_vec()));
        presented.extend(
            intermediates
                .iter()
                .map(|c| CertificateDer::from(c.as_ref().to_vec())),
        );
        if let Some(want) = self.root_ca_hash {
            for c in &presented {
                if pin_eq(&leaf_sha256(c), &want) {
                    let _ = roots.add(c.clone());
                }
            }
        }
        if roots.is_empty() {
            return Err(TlsError::General(
                "sovereign Root CA pin did not match any presented certificate \
                 and no WEISSMAN_SERVER_ROOT_CA_PEM was loaded"
                    .into(),
            ));
        }
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| TlsError::General(format!("sovereign root verifier: {e}")))?;
        verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }
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
        match gateway_trust(&self.leaf_pins, sticky, hash, self.backup_configured()) {
            GatewayTrust::AcceptPinned => {
                if let Ok(mut g) = OBSERVED_PIN.lock() {
                    *g = Some(hash);
                }
                return Ok(ServerCertVerified::assertion());
            }
            GatewayTrust::TrySovereignRoot => {
                match self.verify_sovereign_root(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                ) {
                    Ok(v) => {
                        tracing::warn!(
                            target: "agent",
                            "active TLS leaf pin missed; accepted via sovereign Root CA pin — freezing new leaf"
                        );
                        if let Ok(mut g) = OBSERVED_PIN.lock() {
                            *g = Some(hash);
                        }
                        if let Ok(mut g) = TOFU_PIN.lock() {
                            *g = Some(hash);
                        }
                        PIN_CHANGED.store(true, Ordering::Relaxed);
                        return Ok(v);
                    }
                    Err(e) => {
                        return Err(TlsError::General(format!(
                            "leaf pin missed and sovereign Root CA verification failed: {e}"
                        )));
                    }
                }
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
    let leaf_pins = env_leaf_pins();
    let verifier = Arc::new(WeissmanVerifier {
        inner,
        leaf_pins,
        root_ca_hash: env_root_ca_hash(),
        root_ca_certs: env_root_ca_certs(),
    });
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
            gateway_trust(&[pin], None, pin, false),
            GatewayTrust::AcceptPinned
        );
        assert_eq!(
            gateway_trust(&[pin], None, other, false),
            GatewayTrust::RejectPinMismatch
        );
        assert_eq!(
            gateway_trust(&[], Some(pin), other, false),
            GatewayTrust::RejectPinMismatch
        );
        assert_eq!(
            gateway_trust(&[], None, other, false),
            GatewayTrust::BootstrapPublicRoots
        );
        assert_eq!(
            gateway_trust(&[pin], None, other, true),
            GatewayTrust::TrySovereignRoot,
            "leaf miss with sovereign root configured must try chain verify, not OS store"
        );
        assert_eq!(
            gateway_trust(&[pin, other], None, other, false),
            GatewayTrust::AcceptPinned,
            "backup leaf pin is a second allowed leaf, not a root-hash compare"
        );
    }

    #[test]
    fn pem_certs_parses_one_block() {
        // Tiny invalid DER is fine — parser only splits PEM.
        let der = b"\x30\x00";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let certs = pem_certs(&pem);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), der);
    }

    #[test]
    fn parse_pin_list_comma_separated() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        let pins = parse_pin_list(&format!("{a},{b}"));
        assert_eq!(pins.len(), 2);
    }
}
