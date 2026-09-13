//! DSSE (Dead Simple Signing Envelope) and in-toto attestation verification.
//!
//! Signatures answer "who built/approved this image"; *attestations* answer "and here is the
//! machine-checkable claim they made" — a SLSA provenance record, an SBOM, a vulnerability-scan
//! result. Cosign wraps these in a DSSE envelope, whose defining property is that the signature is
//! computed over a **PAE** (Pre-Authentication Encoding) of `(payloadType, payload)`, not over the
//! payload alone. Verifying the payload bytes without the PAE framing — or ignoring `payloadType` —
//! lets an attacker present a payload of one type as though it were another. We reconstruct the PAE
//! exactly and bind the attestation to the admitted image by matching an in-toto `subject` digest.

use super::image_ref::Digest;
use super::keyring::KeyRing;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;

/// DSSE Pre-Authentication Encoding v1:
/// `"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload`.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[derive(Clone, Debug, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// base64-encoded payload.
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DsseSignature {
    #[serde(default)]
    pub keyid: String,
    /// base64-encoded signature.
    pub sig: String,
}

/// Result of a verified DSSE envelope.
#[derive(Clone, Debug)]
pub struct DsseVerification {
    pub key_id: String,
    pub payload_type: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DsseRejection {
    MalformedEnvelope,
    NoSignatures,
    NoTrustedKeyVerified,
}

impl std::fmt::Display for DsseRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedEnvelope => write!(f, "malformed DSSE envelope"),
            Self::NoSignatures => write!(f, "DSSE envelope carries no signatures"),
            Self::NoTrustedKeyVerified => {
                write!(f, "no trusted key verified any DSSE signature over the PAE")
            }
        }
    }
}

/// Verify a DSSE envelope: at least one signature must verify over `PAE(payloadType, payload)`
/// under a trusted key. The `keyid` in each signature, when non-empty, restricts that signature to
/// a single trusted key (a blank keyid is tried against the whole ring).
pub fn verify_envelope(
    envelope_bytes: &[u8],
    keyring: &KeyRing,
) -> Result<DsseVerification, DsseRejection> {
    let envelope: DsseEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|_| DsseRejection::MalformedEnvelope)?;
    if envelope.signatures.is_empty() {
        return Err(DsseRejection::NoSignatures);
    }
    let payload = BASE64
        .decode(envelope.payload.as_bytes())
        .map_err(|_| DsseRejection::MalformedEnvelope)?;
    let signed = pae(&envelope.payload_type, &payload);

    for signature in &envelope.signatures {
        let Ok(sig) = BASE64.decode(signature.sig.as_bytes()) else {
            continue;
        };
        let hint = if signature.keyid.trim().is_empty() {
            None
        } else {
            Some(signature.keyid.as_str())
        };
        if let Some(key_id) = keyring.verify_any(&signed, &sig, hint) {
            return Ok(DsseVerification {
                key_id,
                payload_type: envelope.payload_type,
                payload,
            });
        }
    }
    Err(DsseRejection::NoTrustedKeyVerified)
}

// ── in-toto statement layer ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub subject: Vec<Subject>,
    #[serde(default)]
    pub predicate: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Subject {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub digest: std::collections::BTreeMap<String, String>,
}

/// A fully verified attestation: DSSE-authenticated, bound to the admitted image, of the required
/// predicate type.
#[derive(Clone, Debug)]
pub struct AttestationVerification {
    pub key_id: String,
    pub predicate_type: String,
    pub statement: InTotoStatement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationRejection {
    Dsse(DsseRejection),
    MalformedStatement,
    PredicateTypeMismatch { required: String, found: String },
    SubjectDigestMismatch,
}

impl std::fmt::Display for AttestationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dsse(d) => write!(f, "{d}"),
            Self::MalformedStatement => write!(f, "malformed in-toto statement"),
            Self::PredicateTypeMismatch { required, found } => {
                write!(
                    f,
                    "predicate type {found} does not match required {required}"
                )
            }
            Self::SubjectDigestMismatch => {
                write!(
                    f,
                    "no attestation subject matches the admitted image digest"
                )
            }
        }
    }
}

/// Verify an attestation envelope and bind it to `image_digest`. When `required_predicate_type` is
/// `Some`, the statement's `predicateType` must match exactly.
pub fn verify_attestation(
    envelope_bytes: &[u8],
    image_digest: &Digest,
    keyring: &KeyRing,
    required_predicate_type: Option<&str>,
) -> Result<AttestationVerification, AttestationRejection> {
    let verified = verify_envelope(envelope_bytes, keyring).map_err(AttestationRejection::Dsse)?;
    let statement: InTotoStatement = serde_json::from_slice(&verified.payload)
        .map_err(|_| AttestationRejection::MalformedStatement)?;

    if let Some(required) = required_predicate_type {
        if statement.predicate_type != required {
            return Err(AttestationRejection::PredicateTypeMismatch {
                required: required.to_string(),
                found: statement.predicate_type.clone(),
            });
        }
    }

    // Bind to the image: some subject must carry the exact digest being admitted.
    let want_alg = image_digest.algorithm();
    let want_hex = image_digest.hex();
    let bound = statement
        .subject
        .iter()
        .any(|s| s.digest.get(want_alg).map(String::as_str) == Some(want_hex));
    if !bound {
        return Err(AttestationRejection::SubjectDigestMismatch);
    }

    Ok(AttestationVerification {
        key_id: verified.key_id,
        predicate_type: statement.predicate_type.clone(),
        statement,
    })
}

#[cfg(test)]
mod tests {
    use super::super::image_ref::Digest;
    use super::super::keyring::{KeyRing, TrustedKey};
    use super::*;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;

    fn ed25519_ring() -> (PKey<Private>, KeyRing) {
        let priv_key = PKey::generate_ed25519().unwrap();
        let pub_pem = priv_key.public_key_to_pem().unwrap();
        let mut ring = KeyRing::new();
        ring.add(TrustedKey::from_pem(&pub_pem, "builder").unwrap());
        (priv_key, ring)
    }

    fn sign_pae(priv_key: &PKey<Private>, payload_type: &str, payload: &[u8]) -> String {
        let signed = pae(payload_type, payload);
        let mut s = Signer::new_without_digest(priv_key).unwrap();
        BASE64.encode(s.sign_oneshot_to_vec(&signed).unwrap())
    }

    fn digest(byte: u8) -> Digest {
        Digest::parse(&("sha256:".to_string() + &format!("{byte:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn pae_matches_spec_vector() {
        // PAE framing: "DSSEv1 SP len(type) SP type SP len(body) SP body".
        // len("http/vnd.in-toto+json") == 21, len("hello world") == 11.
        let out = pae("http/vnd.in-toto+json", b"hello world");
        assert_eq!(out, b"DSSEv1 21 http/vnd.in-toto+json 11 hello world");
    }

    #[test]
    fn valid_attestation_binds_to_image_and_predicate() {
        let (priv_key, ring) = ed25519_ring();
        let d = digest(0x11);
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{ "name": "app", "digest": { "sha256": d.hex() } }],
            "predicate": { "buildDefinition": { "buildType": "https://example.com/ci" } }
        });
        let payload = serde_json::to_vec(&statement).unwrap();
        let payload_type = "application/vnd.in-toto+json";
        let envelope = serde_json::json!({
            "payloadType": payload_type,
            "payload": BASE64.encode(&payload),
            "signatures": [{ "keyid": "", "sig": sign_pae(&priv_key, payload_type, &payload) }]
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let v =
            verify_attestation(&bytes, &d, &ring, Some("https://slsa.dev/provenance/v1")).unwrap();
        assert_eq!(v.predicate_type, "https://slsa.dev/provenance/v1");
    }

    #[test]
    fn attestation_for_other_image_is_rejected() {
        let (priv_key, ring) = ed25519_ring();
        let signed_digest = digest(0x11);
        let admitted_digest = digest(0x22);
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{ "name": "app", "digest": { "sha256": signed_digest.hex() } }],
            "predicate": {}
        });
        let payload = serde_json::to_vec(&statement).unwrap();
        let payload_type = "application/vnd.in-toto+json";
        let envelope = serde_json::json!({
            "payloadType": payload_type,
            "payload": BASE64.encode(&payload),
            "signatures": [{ "keyid": "", "sig": sign_pae(&priv_key, payload_type, &payload) }]
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let err = verify_attestation(&bytes, &admitted_digest, &ring, None).unwrap_err();
        assert_eq!(err, AttestationRejection::SubjectDigestMismatch);
    }

    #[test]
    fn tampered_payload_breaks_pae_signature() {
        let (priv_key, ring) = ed25519_ring();
        let d = digest(0x11);
        let payload_type = "application/vnd.in-toto+json";
        let good_payload = br#"{"_type":"x","predicateType":"p","subject":[]}"#;
        let sig = sign_pae(&priv_key, payload_type, good_payload);
        // Substitute a different payload while keeping the signature.
        let tampered = br#"{"_type":"x","predicateType":"EVIL","subject":[]}"#;
        let envelope = serde_json::json!({
            "payloadType": payload_type,
            "payload": BASE64.encode(tampered),
            "signatures": [{ "keyid": "", "sig": sig }]
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let err = verify_envelope(&bytes, &ring).unwrap_err();
        assert_eq!(err, DsseRejection::NoTrustedKeyVerified);
    }

    #[test]
    fn wrong_predicate_type_rejected() {
        let (priv_key, ring) = ed25519_ring();
        let d = digest(0x11);
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://cyclonedx.org/bom",
            "subject": [{ "name": "app", "digest": { "sha256": d.hex() } }],
            "predicate": {}
        });
        let payload = serde_json::to_vec(&statement).unwrap();
        let payload_type = "application/vnd.in-toto+json";
        let envelope = serde_json::json!({
            "payloadType": payload_type,
            "payload": BASE64.encode(&payload),
            "signatures": [{ "keyid": "", "sig": sign_pae(&priv_key, payload_type, &payload) }]
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let err = verify_attestation(&bytes, &d, &ring, Some("https://slsa.dev/provenance/v1"))
            .unwrap_err();
        assert!(matches!(
            err,
            AttestationRejection::PredicateTypeMismatch { .. }
        ));
    }
}
