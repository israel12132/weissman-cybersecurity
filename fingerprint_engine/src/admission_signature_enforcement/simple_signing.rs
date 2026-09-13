//! Cosign "simple signing" payload — the JSON document a `cosign sign` signature is computed over.
//!
//! A cosign signature does not sign the image bytes directly; it signs a small JSON envelope that
//! *names* the image by its manifest digest. Verification therefore has two independent obligations
//! that must BOTH hold, and conflating them is the classic bypass:
//!   1. the signature is valid over the exact payload bytes under a trusted key, and
//!   2. the digest named inside that payload equals the digest of the image actually being admitted.
//!
//! If (2) is skipped, a valid signature over *some other* image is accepted for *this* image — a
//! confused-deputy admission bypass. We verify the raw payload bytes as delivered (never a
//! re-serialization, whose whitespace/ordering would break the signature) and then compare the
//! embedded digest to the admission target.

use super::image_ref::Digest;
use super::keyring::KeyRing;
use serde::{Deserialize, Serialize};

/// The fixed `critical.type` value cosign writes for a container image signature.
pub const COSIGN_SIGNATURE_TYPE: &str = "cosign container image signature";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleSigningPayload {
    pub critical: Critical,
    #[serde(default)]
    pub optional: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Critical {
    pub identity: Identity,
    pub image: Image,
    #[serde(rename = "type")]
    pub signature_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    #[serde(rename = "docker-reference")]
    pub docker_reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Image {
    #[serde(rename = "docker-manifest-digest")]
    pub docker_manifest_digest: String,
}

impl SimpleSigningPayload {
    /// Construct a canonical payload for `docker_reference` @ `digest`. Used by the control
    /// self-test and by tests; production payloads arrive already signed from the registry.
    #[must_use]
    pub fn new(docker_reference: &str, digest: &Digest) -> Self {
        Self {
            critical: Critical {
                identity: Identity {
                    docker_reference: docker_reference.to_string(),
                },
                image: Image {
                    docker_manifest_digest: digest.to_string(),
                },
                signature_type: COSIGN_SIGNATURE_TYPE.to_string(),
            },
            optional: serde_json::Value::Null,
        }
    }

    /// Serialize to the compact JSON bytes cosign signs over.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Outcome of verifying one cosign keyed signature against one image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedVerification {
    /// The cosign key id that produced the accepted signature.
    pub key_id: String,
    /// The `docker-reference` the signer recorded (informational; the digest is what binds).
    pub docker_reference: String,
}

/// Reason a cosign keyed signature was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyedRejection {
    MalformedPayload,
    WrongPayloadType,
    DigestMismatch { expected: String, found: String },
    NoTrustedKeyVerified,
}

impl std::fmt::Display for KeyedRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedPayload => write!(f, "malformed simple-signing payload"),
            Self::WrongPayloadType => write!(f, "payload critical.type is not a cosign signature"),
            Self::DigestMismatch { expected, found } => {
                write!(
                    f,
                    "signed digest {found} does not match admitted image digest {expected}"
                )
            }
            Self::NoTrustedKeyVerified => {
                write!(
                    f,
                    "no trusted key produced a valid signature over the payload"
                )
            }
        }
    }
}

/// Verify a single cosign keyed signature.
///
/// * `payload_bytes` — the exact bytes of the simple-signing JSON (as stored in the signature).
/// * `signature` — the raw signature bytes (already base64-decoded).
/// * `image_digest` — the digest of the image being admitted; the payload must name this digest.
/// * `keyring` — trusted keys; any one that verifies is sufficient for this signature.
/// * `key_id_hint` — optional cosign key id to restrict verification to a single key.
///
/// # Errors
/// Returns a [`KeyedRejection`] describing the first obligation that failed.
pub fn verify_keyed_signature(
    payload_bytes: &[u8],
    signature: &[u8],
    image_digest: &Digest,
    keyring: &KeyRing,
    key_id_hint: Option<&str>,
) -> Result<KeyedVerification, KeyedRejection> {
    let payload: SimpleSigningPayload =
        serde_json::from_slice(payload_bytes).map_err(|_| KeyedRejection::MalformedPayload)?;

    if payload.critical.signature_type != COSIGN_SIGNATURE_TYPE {
        return Err(KeyedRejection::WrongPayloadType);
    }

    // Obligation (2): the payload must name the exact image we are admitting.
    let signed = Digest::parse(&payload.critical.image.docker_manifest_digest)
        .ok_or(KeyedRejection::MalformedPayload)?;
    if &signed != image_digest {
        return Err(KeyedRejection::DigestMismatch {
            expected: image_digest.to_string(),
            found: signed.to_string(),
        });
    }

    // Obligation (1): a trusted key must have signed these exact bytes.
    match keyring.verify_any(payload_bytes, signature, key_id_hint) {
        Some(key_id) => Ok(KeyedVerification {
            key_id,
            docker_reference: payload.critical.identity.docker_reference,
        }),
        None => Err(KeyedRejection::NoTrustedKeyVerified),
    }
}

#[cfg(test)]
mod tests {
    use super::super::image_ref::Digest;
    use super::super::keyring::{KeyRing, TrustedKey};
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;

    fn signer_key() -> (PKey<Private>, KeyRing) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let priv_key = PKey::from_ec_key(ec).unwrap();
        let pub_pem = priv_key.public_key_to_pem().unwrap();
        let mut ring = KeyRing::new();
        ring.add(TrustedKey::from_pem(&pub_pem, "signer").unwrap());
        (priv_key, ring)
    }

    fn sign(priv_key: &PKey<Private>, bytes: &[u8]) -> Vec<u8> {
        let mut s = Signer::new(MessageDigest::sha256(), priv_key).unwrap();
        s.update(bytes).unwrap();
        s.sign_to_vec().unwrap()
    }

    fn digest(byte: u8) -> Digest {
        Digest::parse(&("sha256:".to_string() + &format!("{byte:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn valid_signature_over_matching_digest_is_accepted() {
        let (priv_key, ring) = signer_key();
        let d = digest(0xab);
        let payload = SimpleSigningPayload::new("ghcr.io/org/app", &d);
        let bytes = payload.to_bytes();
        let sig = sign(&priv_key, &bytes);
        let v = verify_keyed_signature(&bytes, &sig, &d, &ring, None).unwrap();
        assert_eq!(v.docker_reference, "ghcr.io/org/app");
    }

    #[test]
    fn signature_for_a_different_image_is_a_digest_mismatch() {
        let (priv_key, ring) = signer_key();
        let signed_digest = digest(0xab);
        let admitted_digest = digest(0xcd);
        let payload = SimpleSigningPayload::new("ghcr.io/org/app", &signed_digest);
        let bytes = payload.to_bytes();
        let sig = sign(&priv_key, &bytes);
        // Same valid signature, but the image being admitted has a different digest.
        let err = verify_keyed_signature(&bytes, &sig, &admitted_digest, &ring, None).unwrap_err();
        assert!(matches!(err, KeyedRejection::DigestMismatch { .. }));
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let (priv_key, _ring) = signer_key();
        let (_other, empty_ring) = {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let ec = EcKey::generate(&group).unwrap();
            (PKey::from_ec_key(ec).unwrap(), KeyRing::new())
        };
        let d = digest(0xab);
        let payload = SimpleSigningPayload::new("ghcr.io/org/app", &d);
        let bytes = payload.to_bytes();
        let sig = sign(&priv_key, &bytes);
        let err = verify_keyed_signature(&bytes, &sig, &d, &empty_ring, None).unwrap_err();
        assert_eq!(err, KeyedRejection::NoTrustedKeyVerified);
    }

    #[test]
    fn wrong_payload_type_rejected() {
        let (priv_key, ring) = signer_key();
        let d = digest(0xab);
        let mut payload = SimpleSigningPayload::new("ghcr.io/org/app", &d);
        payload.critical.signature_type = "attacker forged type".into();
        let bytes = payload.to_bytes();
        let sig = sign(&priv_key, &bytes);
        let err = verify_keyed_signature(&bytes, &sig, &d, &ring, None).unwrap_err();
        assert_eq!(err, KeyedRejection::WrongPayloadType);
    }
}
