//! The admission policy: what "signed" means for which images in which namespaces, and what the
//! gate does when it does not hold.
//!
//! The policy is the security-relevant configuration surface, so its defaults are chosen to fail
//! safe, and every loosening (an exemption, a break-glass) is explicit, named, and auditable:
//!   * `default_action` is **Deny** — an image no rule matched is refused, not waved through.
//!   * Rules are evaluated in order; the first match wins, so specific rules precede broad ones.
//!   * Exemptions are namespaces (e.g. `kube-system`), never "all unsigned images", and each one
//!     is recorded on the decision so an auditor can see exactly what was allowed to skip.
//!   * Break-glass requires an explicit annotation AND is always recorded as a `break_glass`
//!     decision, never a silent allow.
//!
//! Identity matching for keyless authorities pins BOTH the SAN subject and the OIDC issuer, because
//! a subject alone is forgeable through a different identity provider (see `fulcio`).

use super::fulcio::KeylessIdentity;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

/// A cryptographic authority that can satisfy a signature requirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Authority {
    /// Key-based cosign: a signature by any of these cosign key ids satisfies the authority.
    Keyed { key_ids: Vec<String> },
    /// Keyless (Fulcio): a signing cert whose identity matches any of these identities.
    Keyless {
        identities: Vec<CertificateIdentity>,
    },
}

/// A keyless identity constraint. `subject`/`issuer` are exact; the `_regexp` forms are anchored
/// regular expressions (the whole SAN/issuer must match). At least one subject form and the issuer
/// form should be set; an all-empty identity matches nothing (fail safe).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CertificateIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_regexp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_regexp: Option<String>,
}

impl CertificateIdentity {
    /// True when `identity` satisfies this constraint: some SAN matches the subject form AND the
    /// issuer matches the issuer form. An identity with neither a subject nor an issuer constraint
    /// set never matches (a policy that pins nothing would be a wildcard, which is unsafe here).
    #[must_use]
    pub fn matches(&self, identity: &KeylessIdentity) -> bool {
        let has_subject_constraint = self.subject.is_some() || self.subject_regexp.is_some();
        let has_issuer_constraint = self.issuer.is_some() || self.issuer_regexp.is_some();
        if !has_subject_constraint || !has_issuer_constraint {
            return false;
        }

        let subject_ok = identity.subjects.iter().any(|s| {
            self.subject.as_deref().is_some_and(|want| want == s)
                || self
                    .subject_regexp
                    .as_deref()
                    .is_some_and(|re| anchored_match(re, s))
        });
        if !subject_ok {
            return false;
        }

        let Some(issuer) = identity.issuer.as_deref() else {
            return false;
        };
        self.issuer.as_deref().is_some_and(|want| want == issuer)
            || self
                .issuer_regexp
                .as_deref()
                .is_some_and(|re| anchored_match(re, issuer))
    }
}

/// A required attestation predicate (SLSA provenance, an SBOM, a scan result).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationRequirement {
    /// The in-toto `predicateType` that must be present, DSSE-signed by one of `authorities`.
    pub predicate_type: String,
    /// Authorities allowed to have signed the attestation. Empty means "same as the image
    /// signature authorities" (resolved by the caller).
    #[serde(default)]
    pub authorities: Vec<Authority>,
}

/// What must hold for an image to be admitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Requirement {
    /// Explicitly allow without a signature (audited). Used for narrowly-scoped exempt images.
    Skip,
    /// Require signatures satisfying `threshold` of the listed authorities, optionally a verified
    /// transparency-log entry, and optionally a set of attestations.
    Signed {
        authorities: Vec<Authority>,
        /// Minimum number of authorities that must each produce a valid signature (N-of-M). Each
        /// authority is evaluated independently, so for a genuine N-distinct-signers requirement the
        /// authorities must accept disjoint key ids / identities; otherwise one signature could
        /// satisfy two authorities that share an acceptable signer.
        #[serde(default = "one")]
        threshold: usize,
        /// Require a verified Rekor inclusion proof + SET (mandatory for keyless).
        #[serde(default)]
        require_transparency_log: bool,
        #[serde(default)]
        attestations: Vec<AttestationRequirement>,
    },
}

const fn one() -> usize {
    1
}

/// A rule: an image/namespace match plus the requirement that applies to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageRule {
    pub name: String,
    /// Glob over `registry/repository` (e.g. `ghcr.io/acme/*`, `*`). Matched case-sensitively.
    pub image_glob: String,
    /// Optional glob over the Kubernetes namespace this rule applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_glob: Option<String>,
    pub requirement: Requirement,
}

impl ImageRule {
    #[must_use]
    pub fn matches(&self, image_repository_name: &str, namespace: &str) -> bool {
        if let Some(ns_glob) = &self.namespace_glob {
            if !glob_match(ns_glob, namespace) {
                return false;
            }
        }
        glob_match(&self.image_glob, image_repository_name)
    }
}

/// Break-glass configuration: an annotation-gated emergency bypass, always audited.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreakGlass {
    /// Pod annotation key that activates break-glass (e.g. `admission.weissman.io/break-glass`).
    pub annotation_key: String,
    /// Required annotation value (e.g. an incident id); empty means any non-empty value.
    #[serde(default)]
    pub annotation_value: String,
}

/// The full admission policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    /// Action when no rule matches an image. Hardened default: `Deny`.
    #[serde(default = "deny")]
    pub default_action: Action,
    pub rules: Vec<ImageRule>,
    /// Namespaces whose workloads skip enforcement entirely (recorded on the decision).
    #[serde(default)]
    pub namespace_exemptions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_glass: Option<BreakGlass>,
}

const fn deny() -> Action {
    Action::Deny
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            default_action: Action::Deny,
            rules: Vec::new(),
            namespace_exemptions: Vec::new(),
            break_glass: None,
        }
    }
}

impl AdmissionPolicy {
    /// Parse a policy from JSON.
    pub fn from_json(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("parse admission policy: {e}"))
    }

    /// Parse a policy from YAML.
    pub fn from_yaml(s: &str) -> Result<Self, String> {
        serde_yaml::from_str(s).map_err(|e| format!("parse admission policy: {e}"))
    }

    /// Is this namespace globally exempt from enforcement?
    #[must_use]
    pub fn is_namespace_exempt(&self, namespace: &str) -> bool {
        self.namespace_exemptions
            .iter()
            .any(|n| glob_match(n, namespace))
    }

    /// The first rule matching `image_repository_name` in `namespace`, if any.
    #[must_use]
    pub fn first_matching_rule(
        &self,
        image_repository_name: &str,
        namespace: &str,
    ) -> Option<&ImageRule> {
        self.rules
            .iter()
            .find(|r| r.matches(image_repository_name, namespace))
    }

    /// A hardened starter policy: every image must be keylessly signed by `subject`/`issuer`, with a
    /// verified transparency-log entry. `kube-system` is exempt. This is the "secure by default"
    /// bundle the posture engine renders for operators.
    #[must_use]
    pub fn hardened_starter(subject_regexp: &str, issuer: &str) -> Self {
        Self {
            default_action: Action::Deny,
            rules: vec![ImageRule {
                name: "require-keyless-signature-all-images".to_string(),
                image_glob: "*".to_string(),
                namespace_glob: None,
                requirement: Requirement::Signed {
                    authorities: vec![Authority::Keyless {
                        identities: vec![CertificateIdentity {
                            subject: None,
                            subject_regexp: Some(subject_regexp.to_string()),
                            issuer: Some(issuer.to_string()),
                            issuer_regexp: None,
                        }],
                    }],
                    threshold: 1,
                    require_transparency_log: true,
                    attestations: Vec::new(),
                },
            }],
            namespace_exemptions: vec!["kube-system".to_string()],
            break_glass: None,
        }
    }
}

/// Match `text` against a glob supporting `*` (any run, path-separator-agnostic) and `?`. Falls
/// back to exact match if the pattern fails to compile, so a malformed pattern never widens access.
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match globset::GlobBuilder::new(pattern)
        .literal_separator(false)
        .build()
    {
        Ok(g) => g.compile_matcher().is_match(text),
        Err(_) => pattern == text,
    }
}

/// Whole-string (anchored) regex match. A pattern that fails to compile matches nothing (fail safe).
fn anchored_match(pattern: &str, text: &str) -> bool {
    let anchored = format!("^(?:{pattern})$");
    match regex::Regex::new(&anchored) {
        Ok(re) => re.is_match(text),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(subjects: &[&str], issuer: Option<&str>) -> KeylessIdentity {
        KeylessIdentity {
            subjects: subjects.iter().map(|s| (*s).to_string()).collect(),
            issuer: issuer.map(str::to_string),
            not_before: String::new(),
            not_after: String::new(),
        }
    }

    #[test]
    fn identity_requires_both_subject_and_issuer() {
        let ci = CertificateIdentity {
            subject: Some("ci@example.com".into()),
            issuer: Some("https://accounts.google.com".into()),
            ..Default::default()
        };
        assert!(ci.matches(&identity(
            &["ci@example.com"],
            Some("https://accounts.google.com")
        )));
        // right subject, wrong issuer -> the classic forgery, must fail.
        assert!(!ci.matches(&identity(&["ci@example.com"], Some("https://evil-idp.com"))));
        // right subject, missing issuer -> fail.
        assert!(!ci.matches(&identity(&["ci@example.com"], None)));
    }

    #[test]
    fn identity_regexp_is_anchored() {
        let ci = CertificateIdentity {
            subject_regexp: Some("https://github.com/acme/.*".into()),
            issuer: Some("https://token.actions.githubusercontent.com".into()),
            ..Default::default()
        };
        let iss = Some("https://token.actions.githubusercontent.com");
        assert!(ci.matches(&identity(
            &["https://github.com/acme/repo/.github/workflows/ci.yml@refs/heads/main"],
            iss
        )));
        // A subject that merely CONTAINS the pattern but has an evil suffix must not match
        // (anchoring): here prefix is different host.
        assert!(!ci.matches(&identity(
            &["https://evil.com/https://github.com/acme/x"],
            iss
        )));
    }

    #[test]
    fn empty_identity_matches_nothing() {
        let ci = CertificateIdentity::default();
        assert!(!ci.matches(&identity(&["anything"], Some("anywhere"))));
    }

    #[test]
    fn rule_glob_matches_registry_and_namespace() {
        let rule = ImageRule {
            name: "prod".into(),
            image_glob: "ghcr.io/acme/*".into(),
            namespace_glob: Some("prod-*".into()),
            requirement: Requirement::Skip,
        };
        assert!(rule.matches("ghcr.io/acme/api", "prod-payments"));
        assert!(!rule.matches("ghcr.io/acme/api", "staging"));
        assert!(!rule.matches("docker.io/library/nginx", "prod-payments"));
    }

    #[test]
    fn default_action_is_deny_and_kube_system_exempt() {
        let p = AdmissionPolicy::hardened_starter(
            "https://github.com/acme/.*",
            "https://token.actions.githubusercontent.com",
        );
        assert_eq!(p.default_action, Action::Deny);
        assert!(p.is_namespace_exempt("kube-system"));
        assert!(!p.is_namespace_exempt("default"));
        assert!(p
            .first_matching_rule("ghcr.io/acme/api", "default")
            .is_some());
    }

    #[test]
    fn policy_round_trips_through_yaml() {
        let p = AdmissionPolicy::hardened_starter("s.*", "https://issuer");
        let yaml = serde_yaml::to_string(&p).unwrap();
        let back = AdmissionPolicy::from_yaml(&yaml).unwrap();
        assert_eq!(back.default_action, Action::Deny);
        assert_eq!(back.rules.len(), 1);
    }
}
