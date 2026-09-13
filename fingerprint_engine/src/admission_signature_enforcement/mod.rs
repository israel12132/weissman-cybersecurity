//! # Admission Signature Enforcement
//!
//! Cryptographic verification and approval of container images **before** they are allowed to run
//! in a Kubernetes cluster — the control every serious platform aims for: nothing runs unless a
//! trusted party has cryptographically vouched for the exact bytes of the image.
//!
//! This is defensive security. It answers a single admission-time question with a cryptographic
//! proof rather than a policy label: *"is the image in this Pod signed, by an identity we trust,
//! over the exact digest we are about to run, and was that signature publicly logged?"*.
//!
//! ## Architecture (bottom-up)
//!
//! | Layer | Module | Responsibility |
//! |-------|--------|----------------|
//! | Identity | [`image_ref`] | Parse OCI references; resolve to an immutable `sha256:` digest — the anchor of every signature. |
//! | Primitive | [`keyring`] | Multi-algorithm signature verification (ECDSA P-256/P-384, Ed25519, RSA PKCS#1 / PSS) over OpenSSL; cosign key-ids. |
//! | Cosign | [`simple_signing`] | Verify a keyed cosign signature AND that its payload names the admitted digest (no confused-deputy). |
//! | Attestation | [`dsse`] | DSSE PAE + in-toto: verify SLSA provenance / SBOM attestations, bound to the image. |
//! | Transparency | [`rekor`] | RFC 6962 Merkle inclusion proofs + Signed Entry Timestamp — the trusted clock for keyless. |
//! | Keyless | [`fulcio`] | Verify a Fulcio cert chain, its validity at log time, and its SAN + issuer identity. |
//! | Policy | [`policy`] | What "signed" means for which images/namespaces; fail-closed defaults, N-of-M, break-glass. |
//! | Decision | [`admission`] | `AdmissionReview` → allow/deny across every container of every workload kind, with an audit id. |
//! | Engine | [`posture`] | Live read-only posture probes, a cryptographic control self-test, and a ready-to-apply bundle. |
//!
//! ## What makes it sound (the bypasses it refuses to allow)
//!
//! * **Digest binding.** A signature is trusted only when the digest inside its payload equals the
//!   digest being admitted; a valid signature over a *different* image is rejected.
//! * **Every container.** init / ephemeral / regular containers of Pods and of all workload
//!   controllers are checked — a gate that misses `initContainers` is no gate.
//! * **Fail closed.** Unparseable references, unpinned tags, missing signatures, and unreachable
//!   trust material all deny; the default action is deny.
//! * **Issuer pinning.** Keyless identity pins BOTH the SAN subject and the OIDC issuer — a subject
//!   alone is forgeable through a different identity provider.
//! * **Transparency.** Keyless trust requires a verified Rekor inclusion proof + SET, whose
//!   `integratedTime` is the clock the short-lived Fulcio certificate is validated against.
//!
//! The public verification primitives are re-exported below so other engines (CI/CD, container
//! registry, supply-chain) can reuse the exact same trust core.

pub mod admission;
pub mod der;
pub mod dsse;
pub mod fulcio;
pub mod image_ref;
pub mod keyring;
pub mod policy;
pub mod posture;
pub mod rekor;
pub mod simple_signing;

use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::EngineResult;

// Re-export the trust core for reuse by sibling engines.
pub use admission::{
    evaluate_admission, AdmissionDecision, AdmissionRequest, AdmissionResponse, AdmissionReview,
    EvidenceProvider, ImageEvidence, TrustStore,
};
pub use image_ref::{Digest, ImageReference};
pub use keyring::{KeyRing, SignatureAlgorithm, TrustedKey};
pub use policy::{AdmissionPolicy, Authority, CertificateIdentity, Requirement};

/// The stable engine id registered in `PRODUCTION_ENGINE_IDS`.
pub const ENGINE_ID: &str = "admission_signature_enforcement";

/// Engine entry point wired into `engine_dispatch`. Runs the live posture assessment, the
/// cryptographic control self-test, and renders the hardened enforcement bundle for `target`.
pub async fn run_admission_signature_enforcement_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    posture::run(target, ctx).await
}
