//! The cryptographic trust anchor: a registry of public keys and the multi-algorithm verifier
//! that decides whether a signature over a message was produced by one of them.
//!
//! Every higher layer (cosign simple-signing, DSSE attestations, the Rekor SET) ultimately reduces
//! to "does this signature verify against a trusted public key for this message?". That single
//! operation is the root of the whole enforcement decision, so it is implemented once here, over
//! real OpenSSL primitives, for the algorithms Sigstore actually issues:
//!   * ECDSA P-256 / SHA-256 and P-384 / SHA-384 (Fulcio's ephemeral keys; the common `cosign` key)
//!   * Ed25519 (increasingly used for KMS-backed and offline keys)
//!   * RSA PKCS#1 v1.5 and RSA-PSS over SHA-256 (enterprise HSM / KMS keys)
//!
//! Key identity is the hex SHA-256 of the DER `SubjectPublicKeyInfo` — the exact `keyid` cosign
//! writes into DSSE signatures — so a policy can pin an *N-of-M* set of key ids and match the keys
//! presented at admission time without ambiguity.

use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Signature scheme bound to a public key. The verifier is fully determined by this plus the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    RsaPkcs1Sha256,
    RsaPssSha256,
}

impl SignatureAlgorithm {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Self::Ed25519 => "ed25519",
            Self::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
            Self::RsaPssSha256 => "rsa-pss-sha256",
        }
    }
}

/// A trusted public key with a stable id and a fixed verification scheme.
pub struct TrustedKey {
    key_id: String,
    algorithm: SignatureAlgorithm,
    pkey: PKey<Public>,
    /// Operator-facing label (`kms:prod-signer`, `team-platform`) for audit records.
    pub label: String,
}

impl std::fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print raw key material; the id and scheme are the identifying facts.
        f.debug_struct("TrustedKey")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("label", &self.label)
            .finish()
    }
}

impl TrustedKey {
    /// Load a PEM `SubjectPublicKeyInfo`, auto-selecting the verification scheme from the key type
    /// and curve. RSA keys default to PKCS#1 v1.5 (cosign's default); use [`Self::from_pem_with`]
    /// to pin RSA-PSS.
    pub fn from_pem(pem: &[u8], label: impl Into<String>) -> Result<Self, String> {
        let pkey = PKey::public_key_from_pem(pem).map_err(|e| format!("parse public key: {e}"))?;
        let algorithm = infer_algorithm(&pkey)?;
        Self::finish(pkey, algorithm, label)
    }

    /// Load a PEM public key with an explicit scheme (for RSA-PSS or to override auto-detection).
    pub fn from_pem_with(
        pem: &[u8],
        algorithm: SignatureAlgorithm,
        label: impl Into<String>,
    ) -> Result<Self, String> {
        let pkey = PKey::public_key_from_pem(pem).map_err(|e| format!("parse public key: {e}"))?;
        Self::finish(pkey, algorithm, label)
    }

    /// Build from an already-parsed key (used when a key arrives from an X.509 cert chain).
    pub fn from_pkey(
        pkey: PKey<Public>,
        algorithm: SignatureAlgorithm,
        label: impl Into<String>,
    ) -> Result<Self, String> {
        Self::finish(pkey, algorithm, label)
    }

    /// Build from an already-parsed key, inferring the scheme from the key type and curve. Used for
    /// the ephemeral public key carried by a Fulcio-issued keyless certificate.
    pub fn from_pkey_auto(pkey: PKey<Public>, label: impl Into<String>) -> Result<Self, String> {
        let algorithm = infer_algorithm(&pkey)?;
        Self::finish(pkey, algorithm, label)
    }

    fn finish(
        pkey: PKey<Public>,
        algorithm: SignatureAlgorithm,
        label: impl Into<String>,
    ) -> Result<Self, String> {
        let key_id = compute_key_id(&pkey)?;
        Ok(Self {
            key_id,
            algorithm,
            pkey,
            label: label.into(),
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Verify `signature` over `message`. Returns `true` only on a valid signature; any OpenSSL
    /// error, malformed signature, or algorithm mismatch is a `false`, never a panic.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify_with(&self.pkey, self.algorithm, message, signature)
    }
}

/// Compute the cosign `keyid`: hex-encoded SHA-256 of the DER SubjectPublicKeyInfo.
fn compute_key_id(pkey: &PKey<Public>) -> Result<String, String> {
    let der = pkey
        .public_key_to_der()
        .map_err(|e| format!("encode SPKI: {e}"))?;
    Ok(hex::encode(Sha256::digest(&der)))
}

/// Public helper: the cosign key id for a PEM public key, without building a `TrustedKey`.
pub fn key_id_for_pem(pem: &[u8]) -> Result<String, String> {
    let pkey = PKey::public_key_from_pem(pem).map_err(|e| format!("parse public key: {e}"))?;
    compute_key_id(&pkey)
}

fn infer_algorithm(pkey: &PKey<Public>) -> Result<SignatureAlgorithm, String> {
    match pkey.id() {
        Id::ED25519 => Ok(SignatureAlgorithm::Ed25519),
        Id::RSA => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        Id::EC => {
            let ec = pkey.ec_key().map_err(|e| format!("ec key: {e}"))?;
            match ec.group().curve_name() {
                Some(openssl::nid::Nid::X9_62_PRIME256V1) => {
                    Ok(SignatureAlgorithm::EcdsaP256Sha256)
                }
                Some(openssl::nid::Nid::SECP384R1) => Ok(SignatureAlgorithm::EcdsaP384Sha384),
                other => Err(format!("unsupported EC curve: {other:?}")),
            }
        }
        other => Err(format!("unsupported key type: {other:?}")),
    }
}

fn verify_with(
    pkey: &PKey<Public>,
    algorithm: SignatureAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let result = match algorithm {
        SignatureAlgorithm::Ed25519 => Verifier::new_without_digest(pkey)
            .and_then(|mut v| v.verify_oneshot(signature, message)),
        SignatureAlgorithm::EcdsaP256Sha256 => {
            digest_verify(pkey, MessageDigest::sha256(), message, signature, None)
        }
        SignatureAlgorithm::EcdsaP384Sha384 => {
            digest_verify(pkey, MessageDigest::sha384(), message, signature, None)
        }
        SignatureAlgorithm::RsaPkcs1Sha256 => digest_verify(
            pkey,
            MessageDigest::sha256(),
            message,
            signature,
            Some(Padding::PKCS1),
        ),
        SignatureAlgorithm::RsaPssSha256 => digest_verify(
            pkey,
            MessageDigest::sha256(),
            message,
            signature,
            Some(Padding::PKCS1_PSS),
        ),
    };
    result.unwrap_or(false)
}

fn digest_verify(
    pkey: &PKey<Public>,
    md: MessageDigest,
    message: &[u8],
    signature: &[u8],
    rsa_padding: Option<Padding>,
) -> Result<bool, openssl::error::ErrorStack> {
    let mut verifier = Verifier::new(md, pkey)?;
    if let Some(padding) = rsa_padding {
        verifier.set_rsa_padding(padding)?;
        if padding == Padding::PKCS1_PSS {
            verifier.set_rsa_mgf1_md(md)?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
    }
    verifier.update(message)?;
    verifier.verify(signature)
}

/// A set of trusted keys indexed by cosign key id, used for N-of-M and "any trusted key" checks.
#[derive(Default)]
pub struct KeyRing {
    keys: BTreeMap<String, TrustedKey>,
}

impl KeyRing {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a key. A duplicate key id replaces the prior entry (same key material, newer label).
    pub fn add(&mut self, key: TrustedKey) {
        self.keys.insert(key.key_id().to_string(), key);
    }

    #[must_use]
    pub fn get(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Return the id of the first trusted key that verifies `signature` over `message`, if any.
    /// When `key_id_hint` is set, only that key is tried (the DSSE `keyid` case).
    #[must_use]
    pub fn verify_any(
        &self,
        message: &[u8],
        signature: &[u8],
        key_id_hint: Option<&str>,
    ) -> Option<String> {
        if let Some(hint) = key_id_hint {
            let key = self.keys.get(hint)?;
            return key
                .verify(message, signature)
                .then(|| key.key_id().to_string());
        }
        self.keys
            .values()
            .find(|k| k.verify(message, signature))
            .map(|k| k.key_id().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    fn gen_p256() -> (PKey<openssl::pkey::Private>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let priv_key = PKey::from_ec_key(ec).unwrap();
        let pub_pem = priv_key.public_key_to_pem().unwrap();
        (priv_key, pub_pem)
    }

    fn sign_ecdsa(
        priv_key: &PKey<openssl::pkey::Private>,
        md: MessageDigest,
        msg: &[u8],
    ) -> Vec<u8> {
        let mut signer = Signer::new(md, priv_key).unwrap();
        signer.update(msg).unwrap();
        signer.sign_to_vec().unwrap()
    }

    #[test]
    fn ecdsa_p256_round_trip_and_key_id_stability() {
        let (priv_key, pub_pem) = gen_p256();
        let key = TrustedKey::from_pem(&pub_pem, "prod").unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
        // key id is deterministic and 64 hex chars.
        assert_eq!(key.key_id().len(), 64);
        assert_eq!(key.key_id(), key_id_for_pem(&pub_pem).unwrap());

        let msg = b"cosign container image signature payload";
        let sig = sign_ecdsa(&priv_key, MessageDigest::sha256(), msg);
        assert!(key.verify(msg, &sig));
        // Tampered message must fail.
        assert!(!key.verify(b"different payload", &sig));
        // Truncated / garbage signature must fail, not panic.
        assert!(!key.verify(msg, &sig[..sig.len() - 1]));
        assert!(!key.verify(msg, b""));
    }

    #[test]
    fn ed25519_round_trip() {
        let priv_key = PKey::generate_ed25519().unwrap();
        let pub_pem = priv_key.public_key_to_pem().unwrap();
        let key = TrustedKey::from_pem(&pub_pem, "offline").unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::Ed25519);
        let msg = b"attestation payload";
        let mut signer = Signer::new_without_digest(&priv_key).unwrap();
        let sig = signer.sign_oneshot_to_vec(msg).unwrap();
        assert!(key.verify(msg, &sig));
        assert!(!key.verify(b"tampered", &sig));
    }

    #[test]
    fn rsa_pkcs1_and_pss_round_trip() {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let priv_key = PKey::from_rsa(rsa).unwrap();
        let pub_pem = priv_key.public_key_to_pem().unwrap();
        let msg = b"kms-signed payload";

        // PKCS#1 v1.5 (auto-inferred default for RSA).
        let key1 = TrustedKey::from_pem(&pub_pem, "kms").unwrap();
        assert_eq!(key1.algorithm(), SignatureAlgorithm::RsaPkcs1Sha256);
        let mut s1 = Signer::new(MessageDigest::sha256(), &priv_key).unwrap();
        s1.update(msg).unwrap();
        assert!(key1.verify(msg, &s1.sign_to_vec().unwrap()));

        // RSA-PSS explicit.
        let key2 = TrustedKey::from_pem_with(&pub_pem, SignatureAlgorithm::RsaPssSha256, "kms-pss")
            .unwrap();
        let mut s2 = Signer::new(MessageDigest::sha256(), &priv_key).unwrap();
        s2.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        s2.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        s2.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .unwrap();
        s2.update(msg).unwrap();
        assert!(key2.verify(msg, &s2.sign_to_vec().unwrap()));
    }

    #[test]
    fn keyring_verify_any_and_hint() {
        let (priv_a, pem_a) = gen_p256();
        let (_priv_b, pem_b) = gen_p256();
        let mut ring = KeyRing::new();
        let key_a = TrustedKey::from_pem(&pem_a, "a").unwrap();
        let id_a = key_a.key_id().to_string();
        ring.add(key_a);
        ring.add(TrustedKey::from_pem(&pem_b, "b").unwrap());
        assert_eq!(ring.len(), 2);

        let msg = b"payload";
        let sig = sign_ecdsa(&priv_a, MessageDigest::sha256(), msg);
        assert_eq!(
            ring.verify_any(msg, &sig, None).as_deref(),
            Some(id_a.as_str())
        );
        // A wrong hint (key b) must not verify key a's signature.
        let id_b = key_id_for_pem(&pem_b).unwrap();
        assert!(ring.verify_any(msg, &sig, Some(&id_b)).is_none());
        assert_eq!(
            ring.verify_any(msg, &sig, Some(&id_a)).as_deref(),
            Some(id_a.as_str())
        );
    }
}
