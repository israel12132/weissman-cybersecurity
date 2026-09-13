//! Keyless (Fulcio) certificate identity verification.
//!
//! In keyless Sigstore there is no long-lived key to pin. Instead an ephemeral key signs the image,
//! and Fulcio issues a ten-minute X.509 certificate binding that key to an OIDC identity (the SAN)
//! and the identity provider that asserted it (a Fulcio extension). Trust is then: "I trust any
//! signature whose Fulcio cert chains to the Sigstore root AND whose identity is `X` as asserted by
//! issuer `Y`". Two subtleties are where real deployments get breached:
//!
//!   * **Time.** The cert is long expired by the time we verify. We must NOT check validity against
//!     *now* — we check it against the Rekor `integratedTime`, the trusted moment the signature was
//!     logged. Checking against `now` would reject every legitimate keyless signature; checking
//!     against nothing would accept a signature made with a since-revoked identity.
//!   * **Issuer.** Pinning only the SAN subject (`ci@example.com`) is forgeable by anyone who can
//!     obtain a Fulcio cert for that subject from a *different* OIDC provider. The issuer must be
//!     pinned too, and it lives only in a certificate extension — which we parse ourselves.

use super::der;
use super::keyring::TrustedKey;
use openssl::asn1::Asn1Time;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509StoreContext, X509};
use std::cmp::Ordering;

/// The set of trusted Fulcio roots (and optional trusted intermediates) that a signing cert must
/// chain to.
pub struct FulcioRoots {
    roots: Vec<X509>,
    intermediates: Vec<X509>,
}

impl FulcioRoots {
    /// Build from PEM bundles. `roots_pem` is the trust anchor(s); `intermediates_pem` may hold
    /// intermediate CAs (also acceptable as additional untrusted chain material).
    pub fn from_pem(roots_pem: &[u8], intermediates_pem: &[u8]) -> Result<Self, String> {
        let roots =
            X509::stack_from_pem(roots_pem).map_err(|e| format!("parse Fulcio roots: {e}"))?;
        if roots.is_empty() {
            return Err("no Fulcio root certificates provided".to_string());
        }
        let intermediates = if intermediates_pem.is_empty() {
            Vec::new()
        } else {
            X509::stack_from_pem(intermediates_pem)
                .map_err(|e| format!("parse Fulcio intermediates: {e}"))?
        };
        Ok(Self {
            roots,
            intermediates,
        })
    }
}

/// The identity extracted from a verified keyless certificate.
#[derive(Clone, Debug)]
pub struct KeylessIdentity {
    /// SAN identities (email / URI / DNS) the signer authenticated as.
    pub subjects: Vec<String>,
    /// OIDC issuer that asserted the identity, from the Fulcio issuer extension.
    pub issuer: Option<String>,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FulcioRejection {
    MalformedCertificate,
    ChainVerificationFailed(String),
    OutsideValidityWindow,
    NoIdentity,
}

impl std::fmt::Display for FulcioRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedCertificate => write!(f, "malformed certificate or chain"),
            Self::ChainVerificationFailed(why) => {
                write!(
                    f,
                    "certificate does not chain to a trusted Fulcio root: {why}"
                )
            }
            Self::OutsideValidityWindow => {
                write!(
                    f,
                    "log integration time is outside the certificate validity window"
                )
            }
            Self::NoIdentity => write!(f, "certificate carries no usable SAN identity"),
        }
    }
}

/// Verify a keyless signing certificate: it must chain to a trusted Fulcio root, and the trusted
/// `integrated_time` (from Rekor) must fall within its validity window. On success returns the
/// extracted identity and the leaf's public key as a [`TrustedKey`] ready to verify the signature.
pub fn verify_certificate(
    leaf_pem: &[u8],
    chain_pem: &[u8],
    roots: &FulcioRoots,
    integrated_time: i64,
) -> Result<(KeylessIdentity, TrustedKey), FulcioRejection> {
    let leaf = X509::from_pem(leaf_pem).map_err(|_| FulcioRejection::MalformedCertificate)?;

    // Untrusted chain material: caller-supplied intermediates plus any configured trusted
    // intermediates (offered as untrusted material so path building can use them).
    let mut chain_stack = Stack::new().map_err(|_| FulcioRejection::MalformedCertificate)?;
    if !chain_pem.is_empty() {
        let extra =
            X509::stack_from_pem(chain_pem).map_err(|_| FulcioRejection::MalformedCertificate)?;
        for c in extra {
            let _ = chain_stack.push(c);
        }
    }
    for c in &roots.intermediates {
        let _ = chain_stack.push(c.clone());
    }

    let mut store_builder =
        X509StoreBuilder::new().map_err(|_| FulcioRejection::MalformedCertificate)?;
    for root in &roots.roots {
        store_builder
            .add_cert(root.clone())
            .map_err(|_| FulcioRejection::MalformedCertificate)?;
    }
    // Do NOT check validity against the current wall clock: Fulcio certs are ten-minute-lived and
    // long expired at admission time. We validate the chain, then check the trusted log time
    // against the validity window ourselves.
    store_builder
        .set_flags(X509VerifyFlags::NO_CHECK_TIME)
        .map_err(|_| FulcioRejection::MalformedCertificate)?;
    let store = store_builder.build();

    let mut ctx = X509StoreContext::new().map_err(|_| FulcioRejection::MalformedCertificate)?;
    let chained = ctx
        .init(&store, &leaf, &chain_stack, |c| c.verify_cert())
        .unwrap_or(false);
    if !chained {
        // Re-run to capture the human-readable reason for the audit record.
        let reason = chain_error_reason(&store, &leaf, &chain_stack);
        return Err(FulcioRejection::ChainVerificationFailed(reason));
    }

    // Validity window check against the trusted integration time.
    let at =
        Asn1Time::from_unix(integrated_time).map_err(|_| FulcioRejection::MalformedCertificate)?;
    let not_before = leaf.not_before();
    let not_after = leaf.not_after();
    // notBefore <= integrated_time <= notAfter.
    let after_start = not_before
        .compare(&at)
        .map(|o| o != Ordering::Greater)
        .unwrap_or(false);
    let before_end = at
        .compare(not_after)
        .map(|o| o != Ordering::Greater)
        .unwrap_or(false);
    if !after_start || !before_end {
        return Err(FulcioRejection::OutsideValidityWindow);
    }

    // Extract SAN identities.
    let mut subjects = Vec::new();
    if let Some(names) = leaf.subject_alt_names() {
        for n in &names {
            if let Some(e) = n.email() {
                subjects.push(e.to_string());
            } else if let Some(u) = n.uri() {
                subjects.push(u.to_string());
            } else if let Some(d) = n.dnsname() {
                subjects.push(d.to_string());
            }
        }
    }
    if subjects.is_empty() {
        return Err(FulcioRejection::NoIdentity);
    }

    // Extract the OIDC issuer from the Fulcio extension (v2 preferred, v1 fallback).
    let issuer = leaf.to_der().ok().and_then(|der_bytes| {
        der::certificate_extension(&der_bytes, der::FULCIO_ISSUER_OID_V2)
            .or_else(|| der::certificate_extension(&der_bytes, der::FULCIO_ISSUER_OID_V1))
            .and_then(der::decode_issuer_value)
    });

    let leaf_key = leaf
        .public_key()
        .map_err(|_| FulcioRejection::MalformedCertificate)
        .and_then(|pk| {
            TrustedKey::from_pkey_auto(pk, "fulcio-leaf")
                .map_err(|_| FulcioRejection::MalformedCertificate)
        })?;

    Ok((
        KeylessIdentity {
            subjects,
            issuer,
            not_before: not_before.to_string(),
            not_after: not_after.to_string(),
        },
        leaf_key,
    ))
}

fn chain_error_reason(
    store: &openssl::x509::store::X509Store,
    leaf: &X509,
    chain: &Stack<X509>,
) -> String {
    let mut ctx = match X509StoreContext::new() {
        Ok(c) => c,
        Err(_) => return "context init failed".to_string(),
    };
    let _ = ctx.init(store, leaf, chain, |c| {
        let _ = c.verify_cert();
        Ok(())
    });
    ctx.error().error_string().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
    use openssl::x509::{X509Name, X509};

    fn gen_ec() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn serial() -> openssl::asn1::Asn1Integer {
        let mut bn = BigNum::new().unwrap();
        bn.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        bn.to_asn1_integer().unwrap()
    }

    /// Build a self-signed "root CA" and a leaf signed by it, with a SAN email and validity window
    /// `[not_before, not_after]` (unix seconds). Returns (root_pem, leaf_pem).
    fn root_and_leaf(email: &str, nb: i64, na: i64) -> (Vec<u8>, Vec<u8>, PKey<Private>) {
        let root_key = gen_ec();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "Test Fulcio Root").unwrap();
        let name = name.build();

        let mut rb = X509::builder().unwrap();
        rb.set_version(2).unwrap();
        rb.set_serial_number(&serial()).unwrap();
        rb.set_subject_name(&name).unwrap();
        rb.set_issuer_name(&name).unwrap();
        rb.set_pubkey(&root_key).unwrap();
        rb.set_not_before(&Asn1Time::from_unix(nb - 3600).unwrap())
            .unwrap();
        rb.set_not_after(&Asn1Time::from_unix(na + 3_600_000).unwrap())
            .unwrap();
        let mut bc = BasicConstraints::new();
        rb.append_extension(bc.critical().ca().build().unwrap())
            .unwrap();
        rb.sign(&root_key, MessageDigest::sha256()).unwrap();
        let root = rb.build();

        let leaf_key = gen_ec();
        let mut lname = X509Name::builder().unwrap();
        lname.append_entry_by_text("CN", "signer").unwrap();
        let lname = lname.build();
        let mut lb = X509::builder().unwrap();
        lb.set_version(2).unwrap();
        lb.set_serial_number(&serial()).unwrap();
        lb.set_subject_name(&lname).unwrap();
        lb.set_issuer_name(root.subject_name()).unwrap();
        lb.set_pubkey(&leaf_key).unwrap();
        lb.set_not_before(&Asn1Time::from_unix(nb).unwrap())
            .unwrap();
        lb.set_not_after(&Asn1Time::from_unix(na).unwrap()).unwrap();
        let san = SubjectAlternativeName::new()
            .email(email)
            .build(&lb.x509v3_context(Some(&root), None))
            .unwrap();
        lb.append_extension(san).unwrap();
        lb.sign(&root_key, MessageDigest::sha256()).unwrap();
        let leaf = lb.build();

        (root.to_pem().unwrap(), leaf.to_pem().unwrap(), leaf_key)
    }

    #[test]
    fn valid_chain_and_time_extracts_san() {
        let (root_pem, leaf_pem, _lk) =
            root_and_leaf("ci@example.com", 1_700_000_000, 1_700_000_600);
        let roots = FulcioRoots::from_pem(&root_pem, b"").unwrap();
        let (identity, _key) =
            verify_certificate(&leaf_pem, b"", &roots, 1_700_000_300).expect("valid");
        assert!(identity.subjects.iter().any(|s| s == "ci@example.com"));
    }

    #[test]
    fn integration_time_outside_window_is_rejected() {
        let (root_pem, leaf_pem, _lk) =
            root_and_leaf("ci@example.com", 1_700_000_000, 1_700_000_600);
        let roots = FulcioRoots::from_pem(&root_pem, b"").unwrap();
        // 10 seconds before notBefore.
        let err = verify_certificate(&leaf_pem, b"", &roots, 1_699_999_990).unwrap_err();
        assert_eq!(err, FulcioRejection::OutsideValidityWindow);
        // After notAfter.
        let err2 = verify_certificate(&leaf_pem, b"", &roots, 1_700_001_000).unwrap_err();
        assert_eq!(err2, FulcioRejection::OutsideValidityWindow);
    }

    #[test]
    fn leaf_signed_by_untrusted_root_fails_chain() {
        let (_root_pem, leaf_pem, _lk) =
            root_and_leaf("ci@example.com", 1_700_000_000, 1_700_000_600);
        // A DIFFERENT, unrelated root is the only trust anchor.
        let (other_root_pem, _l2, _lk2) =
            root_and_leaf("other@example.com", 1_700_000_000, 1_700_000_600);
        let roots = FulcioRoots::from_pem(&other_root_pem, b"").unwrap();
        let err = verify_certificate(&leaf_pem, b"", &roots, 1_700_000_300).unwrap_err();
        assert!(matches!(err, FulcioRejection::ChainVerificationFailed(_)));
    }
}
