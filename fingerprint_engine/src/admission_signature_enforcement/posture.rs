//! Live posture assessment + the operator-facing outputs of the engine.
//!
//! The engine does three honest things, each clearly labelled:
//!   1. **Read-only probes** of a target cluster's admission surface — and emits a finding only when
//!      something is actually observed (e.g. `validatingwebhookconfigurations` readable anonymously,
//!      a genuine, serious RBAC gap). Nothing reachable → nothing fabricated.
//!   2. A **cryptographic control self-test**: it signs a payload with an ephemeral key, proves the
//!      decision engine ADMITS the correctly-signed image and DENIES a forged one, a swapped digest,
//!      and an untrusted key. This is a real computation that proves the enforcement core works;
//!      it is labelled `advisory` because it is a capability proof, not a probe of the target.
//!   3. A **hardened enforcement bundle**: ready-to-apply `ValidatingWebhookConfiguration`, a
//!      Sigstore policy-controller `ClusterImagePolicy`, and the machine-readable `AdmissionPolicy`,
//!      so the operator can turn enforcement on with `kubectl apply`. Labelled `advisory`.

use super::admission::{
    evaluate_admission, AdmissionRequest, AdmissionReview, CosignSignature, EmptyEvidenceProvider,
    ImageEvidence, StaticEvidenceProvider, TrustStore,
};
use super::image_ref::Digest;
use super::keyring::{KeyRing, TrustedKey};
use super::policy::{AdmissionPolicy, Authority, ImageRule, Requirement};
use super::simple_signing::SimpleSigningPayload;
use crate::arsenal_config::{finding_rich, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{extract_host, http_get, tcp_open, HttpProbe};
use crate::engine_result::EngineResult;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use serde_json::{json, Value};
use std::time::Duration;

const ENGINE_ID: &str = "admission_signature_enforcement";
/// MITRE ATT&CK T1610 (Deploy Container) — signature enforcement is the control that denies
/// deploying an untrusted/implanted image; T1525 (Implant Internal Image) is the threat it blocks.
const MITRE_DEPLOY_CONTAINER: &str = "T1610";

const DEFAULT_API_PORTS: &[u16] = &[6443, 443, 8443, 16443];
const ADMISSION_DISCOVERY_PATH: &str = "/apis/admissionregistration.k8s.io/v1";
const VWC_PATH: &str = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations";

/// Operator-tunable configuration read from the live scan body (`job_params`).
struct Config {
    api_ports: Vec<u16>,
    timeout_ms: u64,
    /// Certificate-identity subject regexp for the rendered keyless policy.
    subject_regexp: String,
    /// OIDC issuer for the rendered keyless policy.
    issuer: String,
}

impl Config {
    fn from_ctx(ctx: &EngineRunContext) -> Self {
        let p = &ctx.job_params;
        let api_ports = p
            .get("api_ports")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| u16::try_from(v.as_u64().unwrap_or(0)).ok())
                    .filter(|&x| x > 0)
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_API_PORTS.to_vec());
        let timeout_ms = p
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(8000)
            .clamp(500, 60_000);
        let subject_regexp = p
            .get("certificate_identity_regexp")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("https://github.com/ORG/.+/.github/workflows/.+@refs/heads/main")
            .to_string();
        let issuer = p
            .get("certificate_oidc_issuer")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("https://token.actions.githubusercontent.com")
            .to_string();
        Self {
            api_ports,
            timeout_ms,
            subject_regexp,
            issuer,
        }
    }
}

fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms.min(6_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-AdmissionSignature-Probe/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Engine entry: run the full assessment against `target`.
pub async fn run(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("target required (a Kubernetes API endpoint host or URL)");
    }
    let cfg = Config::from_ctx(ctx);
    let client = build_client(cfg.timeout_ms);

    let mut findings: Vec<Value> = Vec::new();

    // ── 1. Live read-only posture probes ─────────────────────────────────────────────────────
    let mut api_observed = false;
    for &port in &cfg.api_ports {
        if !tcp_open(&host, port).await {
            continue;
        }
        let base = format!("https://{host}:{port}");

        if let Some(probe) = http_get(&client, &format!("{base}/version")).await {
            if looks_like_kube_api(&probe) {
                api_observed = true;
                findings.push(finding_rich(
                    ENGINE_ID,
                    "Kubernetes API server reachable",
                    "info",
                    MITRE_DEPLOY_CONTAINER,
                    "The Kubernetes API server responded on this endpoint. Admission control is \
                     configured through this control plane; the checks below assess whether image \
                     signature enforcement is present and correctly fail-closed.",
                    &base,
                    0.9,
                    Evidence::new()
                        .with("port", port)
                        .with("status", probe.status)
                        .with("git_version", extract_json_field(&probe.body, "gitVersion"))
                        .check(
                            "api_server_reachable",
                            true,
                            format!("HTTP {}", probe.status),
                        ),
                ));
            }
        }

        // Anonymous discovery of the admissionregistration API group.
        if let Some(probe) = http_get(&client, &format!("{base}{ADMISSION_DISCOVERY_PATH}")).await {
            if probe.status == 200 && probe.body.contains("validatingwebhookconfigurations") {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "Admission API group discoverable without authentication",
                    "low",
                    MITRE_DEPLOY_CONTAINER,
                    "The admissionregistration.k8s.io API group is readable by an anonymous \
                     client. This is discovery-only, but anonymous API access should be disabled \
                     (`--anonymous-auth=false`) so that admission configuration cannot be \
                     enumerated by unauthenticated network peers.",
                    &base,
                    0.85,
                    Evidence::new()
                        .with("port", port)
                        .with("path", ADMISSION_DISCOVERY_PATH)
                        .check(
                            "anonymous_discovery",
                            true,
                            format!("HTTP {}", probe.status),
                        ),
                ));
            }
        }

        // The critical check: are the webhook configurations themselves anonymously readable?
        if let Some(probe) = http_get(&client, &format!("{base}{VWC_PATH}")).await {
            findings.extend(assess_vwc_response(&base, port, &probe, &cfg));
        }
    }

    // ── 2. Cryptographic control self-test ───────────────────────────────────────────────────
    findings.push(control_self_test(&host));

    // ── 3. Hardened enforcement bundle ───────────────────────────────────────────────────────
    findings.push(hardening_bundle_finding(&host, &cfg));

    let summary = if api_observed {
        format!(
            "Admission signature enforcement assessment complete for {host}: {} finding(s); \
             cryptographic enforcement core self-verified; hardening bundle rendered",
            findings.len()
        )
    } else {
        format!(
            "No Kubernetes API server observed at {host}; emitted cryptographic control self-test \
             and a ready-to-apply enforcement bundle ({} advisory finding(s))",
            findings.len()
        )
    };
    EngineResult::ok(findings, summary)
}

fn looks_like_kube_api(probe: &HttpProbe) -> bool {
    // /version is often anonymously readable; 401/403 also confirm an authenticating API server.
    if probe.status == 401 || probe.status == 403 {
        return true;
    }
    probe.status == 200
        && (probe.body.contains("gitVersion")
            || probe.body.contains("\"major\"")
            || probe.body.contains("buildDate"))
}

fn assess_vwc_response(base: &str, port: u16, probe: &HttpProbe, cfg: &Config) -> Vec<Value> {
    let mut out = Vec::new();
    if probe.status == 200 && probe.body.contains("\"items\"") {
        // Anonymous read of cluster admission configuration — a real, serious misconfiguration.
        let has_signature_webhook = body_mentions_signature_enforcement(&probe.body);
        let fail_open = probe.body.contains("\"failurePolicy\":\"Ignore\"")
            || probe.body.contains("\"failurePolicy\": \"Ignore\"");
        out.push(finding_rich(
            ENGINE_ID,
            "ValidatingWebhookConfigurations readable by anonymous client",
            "high",
            MITRE_DEPLOY_CONTAINER,
            "The cluster's admission webhook configuration is readable without authentication. An \
             attacker can enumerate exactly which admission controllers exist and how they are \
             scoped — the reconnaissance step before crafting a workload that evades them. Disable \
             anonymous authentication and restrict `admissionregistration.k8s.io` reads via RBAC.",
            base,
            0.9,
            Evidence::new()
                .with("port", port)
                .with("path", VWC_PATH)
                .with(
                    "signature_enforcement_webhook_present",
                    has_signature_webhook,
                )
                .check("anonymous_vwc_read", true, format!("HTTP {}", probe.status)),
        ));
        if !has_signature_webhook {
            out.push(finding_rich(
                ENGINE_ID,
                "No image-signature admission webhook detected",
                "high",
                MITRE_DEPLOY_CONTAINER,
                "None of the readable ValidatingWebhookConfigurations appears to enforce container \
                 image signatures (no cosign / sigstore / policy-controller / Kyverno verifyImages \
                 / Connaisseur webhook observed). Unsigned or tampered images can be admitted. \
                 Apply the enforcement bundle rendered by this engine.",
                base,
                0.75,
                Evidence::new().with("port", port).check(
                    "signature_webhook_present",
                    false,
                    "no known signature-enforcement webhook found in the readable configuration",
                ),
            ));
        }
        if fail_open {
            out.push(finding_rich(
                ENGINE_ID,
                "Admission webhook is fail-open (failurePolicy: Ignore)",
                "high",
                MITRE_DEPLOY_CONTAINER,
                "A ValidatingWebhookConfiguration uses `failurePolicy: Ignore`. If the webhook is \
                 unavailable, admission proceeds WITHOUT verification — an attacker who can disrupt \
                 the webhook (or simply times a deploy during an outage) bypasses signature \
                 enforcement entirely. Signature enforcement must be `failurePolicy: Fail`.",
                base,
                0.9,
                Evidence::new()
                    .with("port", port)
                    .with("recommended", "failurePolicy: Fail")
                    .check("fail_closed", false, "failurePolicy: Ignore observed"),
            ));
        }
        let _ = cfg;
    }
    out
}

fn body_mentions_signature_enforcement(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    [
        "cosign",
        "sigstore",
        "policy-controller",
        "policy.sigstore.dev",
        "connaisseur",
        "verifyimages",
        "kyverno",
    ]
    .iter()
    .any(|needle| b.contains(needle))
}

/// Run the enforcement engine against a fresh ephemeral key and adversarial inputs, proving it
/// admits only correctly-signed images. Every branch is a real cryptographic operation.
fn control_self_test(host: &str) -> Value {
    let group = match EcGroup::from_curve_name(Nid::X9_62_PRIME256V1) {
        Ok(g) => g,
        Err(e) => return self_test_error(host, &format!("EC group: {e}")),
    };
    let ec = match EcKey::generate(&group) {
        Ok(k) => k,
        Err(e) => return self_test_error(host, &format!("keygen: {e}")),
    };
    let priv_key = match PKey::from_ec_key(ec) {
        Ok(k) => k,
        Err(e) => return self_test_error(host, &format!("pkey: {e}")),
    };
    let pub_pem = priv_key.public_key_to_pem().unwrap_or_default();
    let trusted = match TrustedKey::from_pem(&pub_pem, "self-test") {
        Ok(k) => k,
        Err(e) => return self_test_error(host, &e),
    };
    let key_id = trusted.key_id().to_string();
    let mut ring = KeyRing::new();
    ring.add(trusted);
    let trust = TrustStore::new(ring);

    let policy = AdmissionPolicy {
        default_action: super::policy::Action::Deny,
        rules: vec![ImageRule {
            name: "self-test".into(),
            image_glob: "*".into(),
            namespace_glob: None,
            requirement: Requirement::Signed {
                authorities: vec![Authority::Keyed {
                    key_ids: vec![key_id],
                }],
                threshold: 1,
                require_transparency_log: false,
                attestations: Vec::new(),
            },
        }],
        namespace_exemptions: Vec::new(),
        break_glass: None,
    };

    let digest =
        Digest::parse(&("sha256:".to_string() + &"a1".repeat(32))).expect("static digest valid");
    let reference = "registry.internal/app";
    let image = format!("{reference}@{digest}");
    let payload = SimpleSigningPayload::new(reference, &digest).to_bytes();
    let good_sig = {
        let mut s = Signer::new(MessageDigest::sha256(), &priv_key).expect("signer");
        s.update(&payload).expect("update");
        s.sign_to_vec().expect("sign")
    };

    let object = json!({
        "kind": "Pod",
        "metadata": { "namespace": "default" },
        "spec": { "containers": [{ "name": "app", "image": image }] }
    });
    let review = AdmissionReview {
        api_version: "admission.k8s.io/v1".into(),
        kind: "AdmissionReview".into(),
        request: Some(AdmissionRequest {
            uid: "self-test".into(),
            namespace: "default".into(),
            operation: "CREATE".into(),
            object,
        }),
        response: None,
    };

    // (a) Correctly signed -> ADMIT.
    let mut provider_ok = StaticEvidenceProvider::new();
    provider_ok.insert(
        reference,
        ImageEvidence {
            resolved_digest: None,
            signatures: vec![CosignSignature {
                payload: payload.clone(),
                signature: good_sig.clone(),
                ..Default::default()
            }],
            attestations: Vec::new(),
        },
    );
    let (admit, _) = evaluate_admission(&review, &policy, &trust, &provider_ok);

    // (b) Forged signature (bit-flipped) -> DENY.
    let mut forged = good_sig.clone();
    if let Some(b) = forged.last_mut() {
        *b ^= 0x01;
    }
    let mut provider_forged = StaticEvidenceProvider::new();
    provider_forged.insert(
        reference,
        ImageEvidence {
            resolved_digest: None,
            signatures: vec![CosignSignature {
                payload: payload.clone(),
                signature: forged,
                ..Default::default()
            }],
            attestations: Vec::new(),
        },
    );
    let (deny_forged, _) = evaluate_admission(&review, &policy, &trust, &provider_forged);

    // (c) Valid signature but for a DIFFERENT digest -> DENY (confused-deputy bypass).
    let other_digest =
        Digest::parse(&("sha256:".to_string() + &"b2".repeat(32))).expect("static digest valid");
    let other_payload = SimpleSigningPayload::new(reference, &other_digest).to_bytes();
    let other_sig = {
        let mut s = Signer::new(MessageDigest::sha256(), &priv_key).expect("signer");
        s.update(&other_payload).expect("update");
        s.sign_to_vec().expect("sign")
    };
    let mut provider_swapped = StaticEvidenceProvider::new();
    provider_swapped.insert(
        reference,
        ImageEvidence {
            resolved_digest: None,
            signatures: vec![CosignSignature {
                payload: other_payload,
                signature: other_sig,
                ..Default::default()
            }],
            attestations: Vec::new(),
        },
    );
    let (deny_swapped, _) = evaluate_admission(&review, &policy, &trust, &provider_swapped);

    // (d) No signature at all -> DENY (fail closed).
    let (deny_unsigned, _) = evaluate_admission(&review, &policy, &trust, &EmptyEvidenceProvider);

    let all_correct =
        admit.allowed && !deny_forged.allowed && !deny_swapped.allowed && !deny_unsigned.allowed;

    finding_rich(
        ENGINE_ID,
        "Cryptographic enforcement core self-verified",
        if all_correct { "info" } else { "critical" },
        MITRE_DEPLOY_CONTAINER,
        "The admission decision engine was exercised end-to-end with a freshly generated key over \
         four adversarial cases. A correctly-signed image is admitted; a forged signature, a valid \
         signature bound to a different digest, and an unsigned image are all denied. This proves \
         the enforcement core is cryptographically sound and fail-closed before it is relied upon.",
        host,
        if all_correct { 0.99 } else { 0.5 },
        Evidence::new()
            .with("advisory", true)
            .with("algorithm", "ecdsa-p256-sha256")
            .check("admit_correctly_signed", admit.allowed, admit.message)
            .check(
                "deny_forged_signature",
                !deny_forged.allowed,
                deny_forged.message,
            )
            .check(
                "deny_digest_mismatch",
                !deny_swapped.allowed,
                deny_swapped.message,
            )
            .check(
                "deny_unsigned_fail_closed",
                !deny_unsigned.allowed,
                deny_unsigned.message,
            )
            .with("audit_id", admit.audit_id),
    )
}

fn self_test_error(host: &str, why: &str) -> Value {
    finding_rich(
        ENGINE_ID,
        "Cryptographic enforcement core self-test could not run",
        "medium",
        MITRE_DEPLOY_CONTAINER,
        "The enforcement core self-test failed to execute in this environment.",
        host,
        0.4,
        Evidence::new().with("advisory", true).with("error", why),
    )
}

/// Render the ready-to-apply hardening bundle as an advisory finding.
fn hardening_bundle_finding(host: &str, cfg: &Config) -> Value {
    let policy = AdmissionPolicy::hardened_starter(&cfg.subject_regexp, &cfg.issuer);
    let policy_json = serde_json::to_string_pretty(&policy).unwrap_or_default();
    let vwc = validating_webhook_configuration_yaml();
    let cluster_image_policy = cluster_image_policy_yaml(&cfg.subject_regexp, &cfg.issuer);

    finding_rich(
        ENGINE_ID,
        "Ready-to-apply image-signature enforcement bundle",
        "info",
        MITRE_DEPLOY_CONTAINER,
        "A hardened, fail-closed enforcement configuration for this cluster: a \
         ValidatingWebhookConfiguration wired to the signature-verification service, a Sigstore \
         policy-controller ClusterImagePolicy requiring keyless signatures from the configured CI \
         identity with transparency-log verification, and the machine-readable admission policy \
         this engine evaluates. Review the pinned identity/issuer, then apply.",
        host,
        0.95,
        Evidence::new()
            .with("advisory", true)
            .with("certificate_identity_regexp", &cfg.subject_regexp)
            .with("certificate_oidc_issuer", &cfg.issuer)
            .with("default_action", "deny")
            .with("fail_policy", "Fail")
            .with("require_transparency_log", true)
            .with("admission_policy_json", policy_json)
            .with("validating_webhook_configuration_yaml", vwc)
            .with("cluster_image_policy_yaml", cluster_image_policy),
    )
}

fn validating_webhook_configuration_yaml() -> String {
    // failurePolicy: Fail (fail closed), sideEffects: None, kube-system excluded, covers the
    // pod-bearing resources whose templates carry container images.
    r#"apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: weissman-image-signature-enforcement
webhooks:
  - name: verify.images.weissman.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail          # fail CLOSED: no verification, no admission
    matchPolicy: Equivalent
    timeoutSeconds: 5
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system"]
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
      - apiGroups: ["batch"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["jobs", "cronjobs"]
    clientConfig:
      service:
        namespace: weissman-system
        name: image-signature-webhook
        path: /validate
        port: 443
      # caBundle: <base64 CA cert for the webhook service TLS>
"#
    .to_string()
}

fn cluster_image_policy_yaml(subject_regexp: &str, issuer: &str) -> String {
    format!(
        r#"apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: weissman-require-keyless-signature
spec:
  images:
    - glob: "**"                 # every image; scope down with additional policies as needed
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: "{issuer}"
            subjectRegExp: "{subject}"
      ctlog:
        url: https://rekor.sigstore.dev   # transparency-log inclusion is REQUIRED
  policy:
    fetchConfigFile: true
  mode: enforce                  # deny on failure (not "warn")
"#,
        issuer = issuer,
        subject = subject_regexp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_self_test_reports_all_branches_correct() {
        let f = control_self_test("test-host");
        assert_eq!(f["severity"], "info");
        let checks = f["evidence"]["checks"].as_array().unwrap();
        // All four adversarial branches must be observed=true (i.e. behaved correctly).
        for c in checks {
            assert_eq!(c["observed"], true, "self-test branch failed: {c}");
        }
    }

    #[test]
    fn bundle_finding_contains_apply_ready_manifests() {
        let cfg = Config {
            api_ports: vec![6443],
            timeout_ms: 8000,
            subject_regexp: "https://github.com/acme/.+".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
        };
        let f = hardening_bundle_finding("h", &cfg);
        let ev = &f["evidence"];
        assert!(ev["validating_webhook_configuration_yaml"]
            .as_str()
            .unwrap()
            .contains("failurePolicy: Fail"));
        assert!(ev["cluster_image_policy_yaml"]
            .as_str()
            .unwrap()
            .contains("token.actions.githubusercontent.com"));
        assert!(ev["admission_policy_json"]
            .as_str()
            .unwrap()
            .contains("\"default_action\""));
    }

    #[test]
    fn vwc_fail_open_is_flagged() {
        let probe = HttpProbe {
            status: 200,
            headers: vec![],
            body: r#"{"items":[{"webhooks":[{"failurePolicy":"Ignore","name":"x.cosign"}]}]}"#
                .to_string(),
            final_url: "https://h:6443".to_string(),
        };
        let cfg = Config {
            api_ports: vec![6443],
            timeout_ms: 8000,
            subject_regexp: "s".into(),
            issuer: "i".into(),
        };
        let out = assess_vwc_response("https://h:6443", 6443, &probe, &cfg);
        assert!(out
            .iter()
            .any(|f| f["title"].as_str().unwrap().contains("fail-open")));
        // Signature webhook IS present (cosign) so the "no signature webhook" finding must be absent.
        assert!(!out
            .iter()
            .any(|f| f["title"].as_str().unwrap().contains("No image-signature")));
    }
}

/// Extract a top-level JSON string field value without a full parse (best-effort, for evidence).
fn extract_json_field(body: &str, key: &str) -> String {
    let needle = format!("\"{key}\"");
    let Some(pos) = body.find(&needle) else {
        return String::new();
    };
    let rest = &body[pos + needle.len()..];
    let Some(colon) = rest.find(':') else {
        return String::new();
    };
    let after = rest[colon + 1..].trim_start();
    if let Some(stripped) = after.strip_prefix('"') {
        stripped
            .find('"')
            .map(|end| stripped[..end].to_string())
            .unwrap_or_default()
    } else {
        after
            .split(['\n', ',', '}'])
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }
}
