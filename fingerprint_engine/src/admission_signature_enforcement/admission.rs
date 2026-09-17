//! The Kubernetes admission decision: turn an `AdmissionReview` request into an allow/deny response
//! by cryptographically verifying every container image against the policy.
//!
//! This is where the layers compose into a single, auditable decision. The design commitments:
//!   * **Fail closed.** Anything we cannot verify — an unparseable reference, a tag we cannot pin to
//!     a digest, missing signatures, a broken chain — is a denial, never a default-allow.
//!   * **Every container.** init, ephemeral, and regular containers of Pods and of every workload
//!     controller (Deployment, StatefulSet, DaemonSet, Job, CronJob, …) are all extracted and
//!     checked. A signature gate that misses `initContainers` is trivially bypassed.
//!   * **Digest binding.** Enforcement is meaningful only against an immutable digest; a signature
//!     over a mutable tag proves nothing about the bytes that will actually run.
//!   * **Auditability.** The decision carries a tamper-evident record id (content hash) and a
//!     structured reason per image, so an approve/deny can be explained after the fact.
//!
//! Signature *material* (cosign signatures, Fulcio certs, attestations, Rekor entries) is supplied
//! by an [`EvidenceProvider`]; production wires this to a live registry + Rekor fetch, while tests
//! and dry-runs use a static provider. The default provider yields nothing — so the default
//! decision for a `Signed` requirement is deny, which is the safe direction.

use super::dsse;
use super::fulcio::{self, FulcioRoots, KeylessIdentity};
use super::image_ref::{Digest, ImageReference};
use super::keyring::{KeyRing, TrustedKey};
use super::policy::{
    Action, AdmissionPolicy, AttestationRequirement, Authority, CertificateIdentity, Requirement,
};
use super::rekor::{self, InclusionProof, LogEntry};
use super::simple_signing;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

// ── Kubernetes AdmissionReview (admission.k8s.io/v1) ─────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionReview {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<AdmissionRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub uid: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub object: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub code: u16,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

// ── Evidence: the signature material for an image ────────────────────────────────────────────────

/// A cosign signature over an image (keyed or keyless), with optional transparency-log proof.
#[derive(Clone, Debug, Default)]
pub struct CosignSignature {
    /// The exact simple-signing payload bytes that were signed.
    pub payload: Vec<u8>,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
    /// Optional cosign key id hint restricting keyed verification to one key.
    pub key_id_hint: Option<String>,
    /// Keyless: the Fulcio leaf certificate (PEM). Absent for key-based signatures.
    pub certificate_pem: Option<Vec<u8>>,
    /// Keyless: intermediate certificates (PEM).
    pub chain_pem: Option<Vec<u8>>,
    /// Transparency-log proof for this signature.
    pub rekor: Option<RekorBundle>,
}

/// A DSSE attestation over an image, with optional transparency-log proof.
#[derive(Clone, Debug, Default)]
pub struct AttestationEvidence {
    /// The DSSE envelope bytes.
    pub envelope: Vec<u8>,
    pub certificate_pem: Option<Vec<u8>>,
    pub chain_pem: Option<Vec<u8>>,
    pub rekor: Option<RekorBundle>,
}

/// A Rekor transparency-log bundle: the entry coordinates, inclusion proof, and SET signature.
#[derive(Clone, Debug)]
pub struct RekorBundle {
    pub entry: LogEntry,
    pub proof: InclusionProof,
    pub set_signature: Vec<u8>,
}

/// All signature material available for one image.
#[derive(Clone, Debug, Default)]
pub struct ImageEvidence {
    /// When the admitted reference is a tag, the digest the provider resolved it to.
    pub resolved_digest: Option<Digest>,
    pub signatures: Vec<CosignSignature>,
    pub attestations: Vec<AttestationEvidence>,
}

/// Supplies evidence for an image. Production fetches from the registry + Rekor; the default yields
/// nothing (so `Signed` requirements deny).
pub trait EvidenceProvider {
    fn evidence_for(&self, image: &ImageReference) -> ImageEvidence;
}

/// The fail-safe default provider: no evidence for anything.
pub struct EmptyEvidenceProvider;
impl EvidenceProvider for EmptyEvidenceProvider {
    fn evidence_for(&self, _image: &ImageReference) -> ImageEvidence {
        ImageEvidence::default()
    }
}

/// A static provider keyed by the image's `registry/repository` name (for tests and dry-runs).
#[derive(Default)]
pub struct StaticEvidenceProvider {
    by_repository: std::collections::HashMap<String, ImageEvidence>,
}

impl StaticEvidenceProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, repository_name: impl Into<String>, evidence: ImageEvidence) {
        self.by_repository.insert(repository_name.into(), evidence);
    }
}

impl EvidenceProvider for StaticEvidenceProvider {
    fn evidence_for(&self, image: &ImageReference) -> ImageEvidence {
        self.by_repository
            .get(&image.repository_name())
            .cloned()
            .unwrap_or_default()
    }
}

// ── Trust material ───────────────────────────────────────────────────────────────────────────────

/// The cryptographic trust anchors used to verify evidence.
pub struct TrustStore {
    /// Trusted keyed cosign keys (for `Authority::Keyed`).
    pub keyring: KeyRing,
    /// Fulcio roots (for `Authority::Keyless`).
    pub fulcio_roots: Option<FulcioRoots>,
    /// The Rekor log's public key (to verify the SET).
    pub rekor_key: Option<TrustedKey>,
}

impl TrustStore {
    #[must_use]
    pub fn new(keyring: KeyRing) -> Self {
        Self {
            keyring,
            fulcio_roots: None,
            rekor_key: None,
        }
    }
}

// ── Decision result (audit) ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
pub struct ImageAssessment {
    pub image: String,
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    pub authorities_satisfied: usize,
    pub transparency_verified: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verified_identities: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AdmissionDecision {
    pub allowed: bool,
    pub message: String,
    pub namespace: String,
    pub request_uid: String,
    pub break_glass: bool,
    pub namespace_exempt: bool,
    pub images: Vec<ImageAssessment>,
    /// Tamper-evident content hash of the decision (immutable audit id).
    pub audit_id: String,
}

impl AdmissionDecision {
    /// Render the Kubernetes `AdmissionResponse` for this decision, echoing the request uid.
    #[must_use]
    pub fn to_response(&self) -> AdmissionResponse {
        AdmissionResponse {
            uid: self.request_uid.clone(),
            allowed: self.allowed,
            status: Some(Status {
                code: if self.allowed { 200 } else { 403 },
                message: self.message.clone(),
                reason: if self.allowed {
                    String::new()
                } else {
                    "AdmissionSignatureEnforcementDenied".to_string()
                },
            }),
            warnings: Vec::new(),
        }
    }
}

// ── Image extraction from arbitrary workload objects ─────────────────────────────────────────────

/// Collect every container image string from a Kubernetes object, across Pod and all workload
/// controllers, and across init / ephemeral / regular containers.
#[must_use]
pub fn extract_images(object: &serde_json::Value) -> Vec<String> {
    let mut images = Vec::new();
    // Pod spec directly, and the templated pod specs of controllers (incl. CronJob's nested one).
    let candidate_specs = [
        object.pointer("/spec"),
        object.pointer("/spec/template/spec"),
        object.pointer("/spec/jobTemplate/spec/template/spec"),
    ];
    for spec in candidate_specs.into_iter().flatten() {
        for field in ["containers", "initContainers", "ephemeralContainers"] {
            if let Some(list) = spec.get(field).and_then(|v| v.as_array()) {
                for c in list {
                    if let Some(img) = c.get("image").and_then(|v| v.as_str()) {
                        let img = img.trim();
                        if !img.is_empty() {
                            images.push(img.to_string());
                        }
                    }
                }
            }
        }
    }
    images.sort();
    images.dedup();
    images
}

/// Read the pod (or template) annotations for break-glass detection.
#[must_use]
fn annotation(object: &serde_json::Value, key: &str) -> Option<String> {
    for ptr in [
        "/metadata/annotations",
        "/spec/template/metadata/annotations",
        "/spec/jobTemplate/spec/template/metadata/annotations",
    ] {
        if let Some(v) = object
            .pointer(ptr)
            .and_then(|a| a.get(key))
            .and_then(|v| v.as_str())
        {
            return Some(v.to_string());
        }
    }
    None
}

// ── Core decision ────────────────────────────────────────────────────────────────────────────────

/// Evaluate an admission request against the policy and trust store, returning the decision and a
/// response-ready `AdmissionReview` (with `request` cleared and `response` set).
#[must_use]
pub fn evaluate_admission(
    review: &AdmissionReview,
    policy: &AdmissionPolicy,
    trust: &TrustStore,
    evidence: &dyn EvidenceProvider,
) -> (AdmissionDecision, AdmissionReview) {
    let decision = decide(review, policy, trust, evidence);
    let response_review = AdmissionReview {
        api_version: review.api_version.clone(),
        kind: review.kind.clone(),
        request: None,
        response: Some(decision.to_response()),
    };
    (decision, response_review)
}

fn decide(
    review: &AdmissionReview,
    policy: &AdmissionPolicy,
    trust: &TrustStore,
    evidence: &dyn EvidenceProvider,
) -> AdmissionDecision {
    let Some(request) = review.request.as_ref() else {
        return finalize(AdmissionDecision {
            allowed: false,
            message: "admission review carried no request".to_string(),
            namespace: String::new(),
            request_uid: String::new(),
            break_glass: false,
            namespace_exempt: false,
            images: Vec::new(),
            audit_id: String::new(),
        });
    };

    let namespace = if request.namespace.is_empty() {
        request
            .object
            .pointer("/metadata/namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string()
    } else {
        request.namespace.clone()
    };

    // Namespace exemption: allowed, but recorded.
    if policy.is_namespace_exempt(&namespace) {
        return finalize(AdmissionDecision {
            allowed: true,
            message: format!("namespace '{namespace}' is exempt from signature enforcement"),
            namespace,
            request_uid: request.uid.clone(),
            break_glass: false,
            namespace_exempt: true,
            images: Vec::new(),
            audit_id: String::new(),
        });
    }

    // Break-glass: an explicit, audited emergency bypass.
    if let Some(bg) = &policy.break_glass {
        if let Some(val) = annotation(&request.object, &bg.annotation_key) {
            let ok = if bg.annotation_value.is_empty() {
                !val.trim().is_empty()
            } else {
                val == bg.annotation_value
            };
            if ok {
                return finalize(AdmissionDecision {
                    allowed: true,
                    message: format!(
                        "break-glass activated via annotation '{}'",
                        bg.annotation_key
                    ),
                    namespace,
                    request_uid: request.uid.clone(),
                    break_glass: true,
                    namespace_exempt: false,
                    images: Vec::new(),
                    audit_id: String::new(),
                });
            }
        }
    }

    let images = extract_images(&request.object);
    if images.is_empty() {
        return finalize(AdmissionDecision {
            allowed: true,
            message: "no container images to enforce".to_string(),
            namespace,
            request_uid: request.uid.clone(),
            break_glass: false,
            namespace_exempt: false,
            images: Vec::new(),
            audit_id: String::new(),
        });
    }

    let mut assessments = Vec::with_capacity(images.len());
    for raw in &images {
        assessments.push(assess_image(raw, &namespace, policy, trust, evidence));
    }
    let all_allowed = assessments.iter().all(|a| a.allowed);
    let denied: Vec<&ImageAssessment> = assessments.iter().filter(|a| !a.allowed).collect();
    let message = if all_allowed {
        format!(
            "all {} image(s) satisfy the signature policy",
            assessments.len()
        )
    } else {
        let details: Vec<String> = denied
            .iter()
            .map(|a| format!("{}: {}", a.image, a.reason))
            .collect();
        format!("denied {} image(s): {}", denied.len(), details.join("; "))
    };

    finalize(AdmissionDecision {
        allowed: all_allowed,
        message,
        namespace,
        request_uid: request.uid.clone(),
        break_glass: false,
        namespace_exempt: false,
        images: assessments,
        audit_id: String::new(),
    })
}

/// Compute the audit id from the decision's stable fields and fill it in.
fn finalize(mut d: AdmissionDecision) -> AdmissionDecision {
    // Hash a canonical projection: uid, namespace, verdict, and per-image (image, allowed, reason).
    let mut h = Sha256::new();
    h.update(d.request_uid.as_bytes());
    h.update([0]);
    h.update(d.namespace.as_bytes());
    h.update([0]);
    h.update([u8::from(d.allowed)]);
    for a in &d.images {
        h.update([0]);
        h.update(a.image.as_bytes());
        h.update([u8::from(a.allowed)]);
        h.update(a.reason.as_bytes());
    }
    d.audit_id = hex::encode(h.finalize());
    d.audit_id.truncate(64);
    d
}

fn assess_image(
    raw: &str,
    namespace: &str,
    policy: &AdmissionPolicy,
    trust: &TrustStore,
    evidence: &dyn EvidenceProvider,
) -> ImageAssessment {
    let Some(image) = ImageReference::parse(raw) else {
        return ImageAssessment {
            image: raw.to_string(),
            allowed: false,
            reason: "unparseable image reference (cannot verify)".to_string(),
            matched_rule: None,
            authorities_satisfied: 0,
            transparency_verified: false,
            verified_identities: Vec::new(),
        };
    };
    let repo_name = image.repository_name();

    let (requirement, matched_rule): (Requirement, Option<String>) =
        match policy.first_matching_rule(&repo_name, namespace) {
            Some(rule) => (rule.requirement.clone(), Some(rule.name.clone())),
            None => match policy.default_action {
                Action::Allow => {
                    return ImageAssessment {
                        image: image.to_string(),
                        allowed: true,
                        reason: "no rule matched; default action is allow".to_string(),
                        matched_rule: None,
                        authorities_satisfied: 0,
                        transparency_verified: false,
                        verified_identities: Vec::new(),
                    };
                }
                Action::Deny => {
                    return ImageAssessment {
                        image: image.to_string(),
                        allowed: false,
                        reason: "no rule matched; default action is deny (fail closed)".to_string(),
                        matched_rule: None,
                        authorities_satisfied: 0,
                        transparency_verified: false,
                        verified_identities: Vec::new(),
                    };
                }
            },
        };

    match requirement {
        Requirement::Skip => ImageAssessment {
            image: image.to_string(),
            allowed: true,
            reason: "rule permits this image without a signature (skip)".to_string(),
            matched_rule,
            authorities_satisfied: 0,
            transparency_verified: false,
            verified_identities: Vec::new(),
        },
        Requirement::Signed {
            authorities,
            threshold,
            require_transparency_log,
            attestations,
        } => {
            let ev = evidence.evidence_for(&image);
            // Enforcement requires an immutable digest.
            let Some(digest) = image.digest.clone().or_else(|| ev.resolved_digest.clone()) else {
                return ImageAssessment {
                    image: image.to_string(),
                    allowed: false,
                    reason: "image is not digest-pinned and no digest could be resolved; \
                             signature enforcement requires a sha256 digest"
                        .to_string(),
                    matched_rule,
                    authorities_satisfied: 0,
                    transparency_verified: false,
                    verified_identities: Vec::new(),
                };
            };

            let proof = verify_signed(
                &digest,
                &authorities,
                threshold,
                require_transparency_log,
                &attestations,
                &ev,
                trust,
            );
            match proof {
                Ok(p) => ImageAssessment {
                    image: image.to_string(),
                    allowed: true,
                    reason: format!(
                        "verified: {}/{} authorities satisfied{}",
                        p.authorities_satisfied,
                        threshold,
                        if p.transparency_verified {
                            ", transparency log verified"
                        } else {
                            ""
                        }
                    ),
                    matched_rule,
                    authorities_satisfied: p.authorities_satisfied,
                    transparency_verified: p.transparency_verified,
                    verified_identities: p.identities,
                },
                Err(reason) => ImageAssessment {
                    image: image.to_string(),
                    allowed: false,
                    reason,
                    matched_rule,
                    authorities_satisfied: 0,
                    transparency_verified: false,
                    verified_identities: Vec::new(),
                },
            }
        }
    }
}

/// Aggregate proof for a satisfied `Signed` requirement.
struct SignedProof {
    authorities_satisfied: usize,
    transparency_verified: bool,
    identities: Vec<String>,
}

fn verify_signed(
    digest: &Digest,
    authorities: &[Authority],
    threshold: usize,
    require_tlog: bool,
    attestations: &[AttestationRequirement],
    evidence: &ImageEvidence,
    trust: &TrustStore,
) -> Result<SignedProof, String> {
    if authorities.is_empty() {
        return Err("policy rule lists no authorities; nothing can satisfy it".to_string());
    }
    // Fail closed on a misconfigured threshold of 0: a `Signed` requirement must always demand at
    // least one valid signature.
    let threshold = threshold.max(1);
    let mut satisfied = 0usize;
    let mut any_tlog = false;
    let mut identities = Vec::new();

    for authority in authorities {
        if let Some(proof) =
            authority_satisfied_by_signatures(authority, digest, require_tlog, evidence, trust)
        {
            satisfied += 1;
            any_tlog |= proof.tlog_verified;
            if let Some(id) = proof.identity {
                identities.push(id);
            } else if let Some(kid) = proof.key_id {
                identities.push(format!("key:{kid}"));
            }
        }
    }

    if satisfied < threshold {
        return Err(format!(
            "only {satisfied} of required {threshold} authorities produced a valid signature"
        ));
    }

    // Attestation requirements: each must be independently satisfied.
    for req in attestations {
        let effective = if req.authorities.is_empty() {
            authorities
        } else {
            req.authorities.as_slice()
        };
        if !attestation_satisfied(req, effective, digest, evidence, trust) {
            return Err(format!(
                "required attestation '{}' is missing or not validly signed",
                req.predicate_type
            ));
        }
    }

    Ok(SignedProof {
        authorities_satisfied: satisfied,
        transparency_verified: any_tlog,
        identities,
    })
}

struct AuthorityProof {
    key_id: Option<String>,
    identity: Option<String>,
    tlog_verified: bool,
}

fn authority_satisfied_by_signatures(
    authority: &Authority,
    digest: &Digest,
    require_tlog: bool,
    evidence: &ImageEvidence,
    trust: &TrustStore,
) -> Option<AuthorityProof> {
    for sig in &evidence.signatures {
        match authority {
            Authority::Keyed { key_ids } => {
                if sig.certificate_pem.is_some() {
                    continue; // keyless material cannot satisfy a keyed authority
                }
                let Ok(v) = simple_signing::verify_keyed_signature(
                    &sig.payload,
                    &sig.signature,
                    digest,
                    &trust.keyring,
                    sig.key_id_hint.as_deref(),
                ) else {
                    continue;
                };
                if !key_ids.iter().any(|k| k == &v.key_id) {
                    continue; // verified by a trusted key, but not one this authority accepts
                }
                let tlog = verify_signature_tlog(sig, trust);
                if require_tlog && !tlog {
                    continue;
                }
                return Some(AuthorityProof {
                    key_id: Some(v.key_id),
                    identity: None,
                    tlog_verified: tlog,
                });
            }
            Authority::Keyless { identities } => {
                let Some(bundle) = &sig.rekor else {
                    continue; // keyless needs a trusted time from the log
                };
                let Some(cert) = &sig.certificate_pem else {
                    continue;
                };
                let Some(roots) = &trust.fulcio_roots else {
                    continue;
                };
                let Some(rekor_key) = &trust.rekor_key else {
                    continue;
                };
                let tlog = rekor::verify_entry(
                    &bundle.entry,
                    &bundle.proof,
                    &bundle.set_signature,
                    rekor_key,
                );
                if !tlog.is_fully_verified() {
                    continue;
                }
                let Ok((identity, leaf_key)) = fulcio::verify_certificate(
                    cert,
                    sig.chain_pem.as_deref().unwrap_or(b""),
                    roots,
                    tlog.integrated_time,
                ) else {
                    continue;
                };
                if !identity_matches_any(identities, &identity) {
                    continue;
                }
                // The signature itself must verify under the certified leaf key.
                let mut ring = KeyRing::new();
                ring.add(leaf_key);
                if simple_signing::verify_keyed_signature(
                    &sig.payload,
                    &sig.signature,
                    digest,
                    &ring,
                    None,
                )
                .is_err()
                {
                    continue;
                }
                return Some(AuthorityProof {
                    key_id: None,
                    identity: Some(describe_identity(&identity)),
                    tlog_verified: true,
                });
            }
        }
    }
    None
}

fn verify_signature_tlog(sig: &CosignSignature, trust: &TrustStore) -> bool {
    let (Some(bundle), Some(rekor_key)) = (&sig.rekor, &trust.rekor_key) else {
        return false;
    };
    rekor::verify_entry(
        &bundle.entry,
        &bundle.proof,
        &bundle.set_signature,
        rekor_key,
    )
    .is_fully_verified()
}

fn attestation_satisfied(
    req: &AttestationRequirement,
    authorities: &[Authority],
    digest: &Digest,
    evidence: &ImageEvidence,
    trust: &TrustStore,
) -> bool {
    for att in &evidence.attestations {
        for authority in authorities {
            match authority {
                Authority::Keyed { key_ids } => {
                    if att.certificate_pem.is_some() {
                        continue;
                    }
                    if let Ok(v) = dsse::verify_attestation(
                        &att.envelope,
                        digest,
                        &trust.keyring,
                        Some(&req.predicate_type),
                    ) {
                        if key_ids.iter().any(|k| k == &v.key_id) {
                            return true;
                        }
                    }
                }
                Authority::Keyless { identities } => {
                    let (Some(bundle), Some(cert), Some(roots), Some(rekor_key)) = (
                        &att.rekor,
                        &att.certificate_pem,
                        &trust.fulcio_roots,
                        &trust.rekor_key,
                    ) else {
                        continue;
                    };
                    let tlog = rekor::verify_entry(
                        &bundle.entry,
                        &bundle.proof,
                        &bundle.set_signature,
                        rekor_key,
                    );
                    if !tlog.is_fully_verified() {
                        continue;
                    }
                    let Ok((identity, leaf_key)) = fulcio::verify_certificate(
                        cert,
                        att.chain_pem.as_deref().unwrap_or(b""),
                        roots,
                        tlog.integrated_time,
                    ) else {
                        continue;
                    };
                    if !identity_matches_any(identities, &identity) {
                        continue;
                    }
                    let mut ring = KeyRing::new();
                    ring.add(leaf_key);
                    if dsse::verify_attestation(
                        &att.envelope,
                        digest,
                        &ring,
                        Some(&req.predicate_type),
                    )
                    .is_ok()
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn identity_matches_any(identities: &[CertificateIdentity], identity: &KeylessIdentity) -> bool {
    identities.iter().any(|ci| ci.matches(identity))
}

fn describe_identity(identity: &KeylessIdentity) -> String {
    let subject = identity.subjects.first().map_or("?", String::as_str);
    match &identity.issuer {
        Some(iss) => format!("{subject} ({iss})"),
        None => subject.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::image_ref::Digest;
    use super::super::keyring::{KeyRing, TrustedKey};
    use super::super::policy::{AdmissionPolicy, Authority, ImageRule, Requirement};
    use super::super::simple_signing::SimpleSigningPayload;
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::sign::Signer;

    fn keyed_signer() -> (PKey<Private>, TrustedKey, String) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let priv_key = PKey::from_ec_key(ec).unwrap();
        let pem = priv_key.public_key_to_pem().unwrap();
        let key = TrustedKey::from_pem(&pem, "prod-signer").unwrap();
        let id = key.key_id().to_string();
        (priv_key, key, id)
    }

    fn sign_bytes(priv_key: &PKey<Private>, bytes: &[u8]) -> Vec<u8> {
        let mut s = Signer::new(MessageDigest::sha256(), priv_key).unwrap();
        s.update(bytes).unwrap();
        s.sign_to_vec().unwrap()
    }

    fn digest_for(byte: u8) -> Digest {
        Digest::parse(&("sha256:".to_string() + &format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn pod_object(image: &str, namespace: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": "Pod",
            "metadata": { "namespace": namespace },
            "spec": {
                "initContainers": [{ "name": "init", "image": image }],
                "containers": [{ "name": "app", "image": image }]
            }
        })
    }

    fn review_for(object: serde_json::Value, namespace: &str) -> AdmissionReview {
        AdmissionReview {
            api_version: "admission.k8s.io/v1".into(),
            kind: "AdmissionReview".into(),
            request: Some(AdmissionRequest {
                uid: "req-123".into(),
                namespace: namespace.into(),
                operation: "CREATE".into(),
                object,
            }),
            response: None,
        }
    }

    fn keyed_policy(key_id: &str) -> AdmissionPolicy {
        AdmissionPolicy {
            default_action: Action::Deny,
            rules: vec![ImageRule {
                name: "require-prod-key".into(),
                image_glob: "ghcr.io/acme/*".into(),
                namespace_glob: None,
                requirement: Requirement::Signed {
                    authorities: vec![Authority::Keyed {
                        key_ids: vec![key_id.to_string()],
                    }],
                    threshold: 1,
                    require_transparency_log: false,
                    attestations: Vec::new(),
                },
            }],
            namespace_exemptions: vec!["kube-system".into()],
            break_glass: None,
        }
    }

    fn signed_evidence(
        priv_key: &PKey<Private>,
        reference: &str,
        digest: &Digest,
    ) -> ImageEvidence {
        let payload = SimpleSigningPayload::new(reference, digest).to_bytes();
        let signature = sign_bytes(priv_key, &payload);
        ImageEvidence {
            resolved_digest: None,
            signatures: vec![CosignSignature {
                payload,
                signature,
                ..Default::default()
            }],
            attestations: Vec::new(),
        }
    }

    #[test]
    fn signed_image_is_admitted() {
        let (priv_key, key, key_id) = keyed_signer();
        let digest = digest_for(0xab);
        let img = format!("ghcr.io/acme/api@{digest}");
        let mut ring = KeyRing::new();
        ring.add(key);
        let trust = TrustStore::new(ring);
        let policy = keyed_policy(&key_id);

        let mut provider = StaticEvidenceProvider::new();
        provider.insert(
            "ghcr.io/acme/api",
            signed_evidence(&priv_key, "ghcr.io/acme/api", &digest),
        );

        let review = review_for(pod_object(&img, "default"), "default");
        let (decision, response) = evaluate_admission(&review, &policy, &trust, &provider);
        assert!(decision.allowed, "decision: {decision:?}");
        assert_eq!(decision.images.len(), 1);
        assert_eq!(response.response.unwrap().allowed, true);
        assert_eq!(decision.audit_id.len(), 64);
    }

    #[test]
    fn unsigned_image_is_denied_fail_closed() {
        let (_priv, key, key_id) = keyed_signer();
        let digest = digest_for(0xab);
        let img = format!("ghcr.io/acme/api@{digest}");
        let mut ring = KeyRing::new();
        ring.add(key);
        let trust = TrustStore::new(ring);
        let policy = keyed_policy(&key_id);

        // No evidence at all.
        let provider = EmptyEvidenceProvider;
        let review = review_for(pod_object(&img, "default"), "default");
        let (decision, _r) = evaluate_admission(&review, &policy, &trust, &provider);
        assert!(!decision.allowed);
        assert!(decision.message.contains("denied"));
    }

    #[test]
    fn signature_from_untrusted_key_is_denied() {
        let (attacker_priv, _attacker_key, _aid) = keyed_signer();
        let (_priv, trusted_key, trusted_id) = keyed_signer();
        let digest = digest_for(0xab);
        let img = format!("ghcr.io/acme/api@{digest}");
        let mut ring = KeyRing::new();
        ring.add(trusted_key); // only the trusted key is in the ring
        let trust = TrustStore::new(ring);
        let policy = keyed_policy(&trusted_id);

        // Evidence signed by the attacker's key.
        let mut provider = StaticEvidenceProvider::new();
        provider.insert(
            "ghcr.io/acme/api",
            signed_evidence(&attacker_priv, "ghcr.io/acme/api", &digest),
        );
        let review = review_for(pod_object(&img, "default"), "default");
        let (decision, _r) = evaluate_admission(&review, &policy, &trust, &provider);
        assert!(!decision.allowed);
    }

    #[test]
    fn tag_only_image_is_denied_without_digest() {
        let (priv_key, key, key_id) = keyed_signer();
        let digest = digest_for(0xab);
        let mut ring = KeyRing::new();
        ring.add(key);
        let trust = TrustStore::new(ring);
        let policy = keyed_policy(&key_id);

        // Evidence exists and is validly signed, but the admitted image is a bare tag with no
        // resolved digest -> must be denied (cannot bind signature to bytes).
        let mut provider = StaticEvidenceProvider::new();
        provider.insert(
            "ghcr.io/acme/api",
            signed_evidence(&priv_key, "ghcr.io/acme/api", &digest),
        );
        let review = review_for(pod_object("ghcr.io/acme/api:v1", "default"), "default");
        let (decision, _r) = evaluate_admission(&review, &policy, &trust, &provider);
        assert!(!decision.allowed);
        assert!(decision.images[0].reason.contains("digest"));
    }

    #[test]
    fn kube_system_is_exempt() {
        let (_priv, key, key_id) = keyed_signer();
        let mut ring = KeyRing::new();
        ring.add(key);
        let trust = TrustStore::new(ring);
        let policy = keyed_policy(&key_id);
        let provider = EmptyEvidenceProvider;
        let review = review_for(
            pod_object("ghcr.io/acme/api:v1", "kube-system"),
            "kube-system",
        );
        let (decision, _r) = evaluate_admission(&review, &policy, &trust, &provider);
        assert!(decision.allowed);
        assert!(decision.namespace_exempt);
    }

    #[test]
    fn extract_images_covers_all_container_types_and_controllers() {
        let deployment = serde_json::json!({
            "kind": "Deployment",
            "spec": { "template": { "spec": {
                "initContainers": [{ "image": "reg/init:1" }],
                "containers": [{ "image": "reg/app:2" }],
                "ephemeralContainers": [{ "image": "reg/debug:3" }]
            }}}
        });
        let imgs = extract_images(&deployment);
        assert!(imgs.contains(&"reg/init:1".to_string()));
        assert!(imgs.contains(&"reg/app:2".to_string()));
        assert!(imgs.contains(&"reg/debug:3".to_string()));

        let cronjob = serde_json::json!({
            "kind": "CronJob",
            "spec": { "jobTemplate": { "spec": { "template": { "spec": {
                "containers": [{ "image": "reg/cron:9" }]
            }}}}}
        });
        assert!(extract_images(&cronjob).contains(&"reg/cron:9".to_string()));
    }

    #[test]
    fn break_glass_allows_with_audit() {
        let (_priv, key, key_id) = keyed_signer();
        let mut ring = KeyRing::new();
        ring.add(key);
        let trust = TrustStore::new(ring);
        let mut policy = keyed_policy(&key_id);
        policy.break_glass = Some(super::super::policy::BreakGlass {
            annotation_key: "admission.weissman.io/break-glass".into(),
            annotation_value: String::new(),
        });
        let object = serde_json::json!({
            "kind": "Pod",
            "metadata": {
                "namespace": "default",
                "annotations": { "admission.weissman.io/break-glass": "INC-4471" }
            },
            "spec": { "containers": [{ "image": "ghcr.io/acme/api:v1" }] }
        });
        let review = review_for(object, "default");
        let provider = EmptyEvidenceProvider;
        let (decision, _r) = evaluate_admission(&review, &policy, &trust, &provider);
        assert!(decision.allowed);
        assert!(decision.break_glass);
    }
}
