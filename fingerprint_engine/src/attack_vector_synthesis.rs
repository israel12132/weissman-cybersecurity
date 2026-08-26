//! Cross-domain attack-vector synthesis.
//!
//! Single engines report single weaknesses. Real breaches chain weaknesses across domains — an SSRF
//! that reaches a cloud metadata endpoint, a leaked secret that lands because MFA is off, a
//! session-replay SDK that captures credentials a missing CSP lets exfiltrate. This module fuses the
//! findings a tenant already has into named, multi-stage **attack vectors** that no individual
//! engine surfaces, each with a MITRE technique chain, an evidence-derived confidence, a novelty
//! rating, and prioritized remediation.
//!
//! It invents nothing: every vector is gated on real findings. A rule only fires when *all* of its
//! required preconditions are matched by findings actually present for the tenant, so a vector is
//! always backed by concrete evidence rows (returned in `evidence`). The core is pure and
//! unit-tested; the HTTP layer only loads findings and serializes the result.

use serde::Serialize;
use serde_json::{json, Value};

/// A minimal projection of a finding — everything synthesis needs, nothing it does not.
#[derive(Debug, Clone)]
pub struct FindingLite {
    pub id: String,
    pub engine: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub client_id: Option<i64>,
}

impl FindingLite {
    fn haystack(&self) -> String {
        format!(
            "{} {} {}",
            self.engine.to_ascii_lowercase(),
            self.title.to_ascii_lowercase(),
            self.description.to_ascii_lowercase()
        )
    }
}

/// One precondition of a fusion rule: a domain signal matched by engine id and/or free-text.
struct Precondition {
    label: &'static str,
    /// Engine-id substrings that satisfy this precondition (e.g. "ssrf", "cloud").
    engines: &'static [&'static str],
    /// Title/description keywords that satisfy it (e.g. "metadata", "169.254").
    keywords: &'static [&'static str],
    /// When true the rule cannot fire unless this precondition is matched by some finding.
    required: bool,
}

/// A composite attack-vector definition. Data-driven so rules read as a table and are easy to audit.
struct VectorRule {
    id: &'static str,
    name: &'static str,
    /// Severity floor; the emitted severity is escalated from matched-finding severity but never
    /// drops below this.
    base_severity: &'static str,
    /// 1..5 — how rarely this cross-domain chain is detected elsewhere (higher = more novel).
    novelty: u8,
    tactics: &'static [&'static str],
    mitre_chain: &'static [&'static str],
    narrative: &'static str,
    business_impact: &'static str,
    recommended_actions: &'static [&'static str],
    preconditions: &'static [Precondition],
}

/// A synthesized attack vector, ready to serialize to the API.
#[derive(Debug, Clone, Serialize)]
pub struct AttackVector {
    pub id: String,
    pub name: String,
    pub severity: String,
    /// 0..1 — matched preconditions / total preconditions.
    pub confidence: f64,
    pub novelty: u8,
    /// severity_rank(severity) * confidence * novelty, for ranking.
    pub priority: f64,
    pub tactics: Vec<String>,
    pub mitre_chain: Vec<String>,
    pub narrative: String,
    pub business_impact: String,
    pub recommended_actions: Vec<String>,
    pub matched_preconditions: Vec<String>,
    /// The concrete findings that evidence this vector.
    pub evidence: Vec<Value>,
    pub client_id: Option<i64>,
}

fn severity_rank(s: &str) -> i32 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn rank_to_severity(rank: i32) -> &'static str {
    match rank {
        r if r >= 5 => "critical",
        4 => "high",
        3 => "medium",
        2 => "low",
        _ => "info",
    }
}

fn precondition_matches(pc: &Precondition, f: &FindingLite) -> bool {
    let engine = f.engine.to_ascii_lowercase();
    if pc.engines.iter().any(|e| engine.contains(e)) {
        return true;
    }
    let hay = f.haystack();
    pc.keywords.iter().any(|k| hay.contains(k))
}

/// The rule table. Each entry fuses two or more domains into a chain that a single engine cannot see.
const RULES: &[VectorRule] = &[
    VectorRule {
        id: "cloud_imds_credential_theft",
        name: "SSRF → Cloud IMDS credential theft → account takeover",
        base_severity: "critical",
        novelty: 5,
        tactics: &["TA0001", "TA0006", "TA0004"],
        mitre_chain: &["T1190", "T1552.005", "T1078.004"],
        narrative: "A server-side request forgery reachable on the external surface can be pointed at the cloud instance metadata service (169.254.169.254). Combined with the exposed cloud posture, an attacker harvests short-lived IAM credentials from IMDS and assumes the workload role — turning one web bug into cloud account takeover.",
        business_impact: "Full compromise of the cloud workload identity and any data/role it can reach; typical blast radius is the entire account.",
        recommended_actions: &[
            "Enforce IMDSv2 (hop-limit 1, session tokens) on every instance and block 169.254.169.254 at the app egress.",
            "Add an allow-list to the SSRF-prone endpoint and reject link-local / metadata hosts.",
            "Scope the workload IAM role to least privilege so a stolen token is low-value.",
        ],
        preconditions: &[
            Precondition { label: "Server-side request forgery reachable", engines: &["ssrf"], keywords: &["ssrf", "server-side request forgery"], required: true },
            Precondition { label: "Cloud metadata / posture exposure", engines: &["cloud", "aws", "azure", "gcp"], keywords: &["metadata", "169.254", "imds", "instance metadata"], required: true },
        ],
    },
    VectorRule {
        id: "client_side_credential_capture",
        name: "Client-side keystroke capture → credential exfiltration",
        base_severity: "high",
        novelty: 4,
        tactics: &["TA0009", "TA0006", "TA0010"],
        mitre_chain: &["T1056.001", "T1059.007", "T1041"],
        narrative: "Input-capture code (a keylogger or an unmasked session-replay SDK) runs on a page whose Content-Security-Policy is missing or permissive. Anything a user types — including credentials into the login form — can be captured and beaconed to an attacker-controlled origin with no CSP to block the exfiltration channel.",
        business_impact: "Silent theft of user and admin credentials at scale; a reportable data exposure under most privacy regimes.",
        recommended_actions: &[
            "Deploy a strict CSP (connect-src / script-src allow-lists) so captured data cannot be exfiltrated to arbitrary origins.",
            "Remove or field-mask session-replay/keystroke SDKs on any page with a credential or payment field.",
            "Subresource-integrity-pin third-party scripts and review them for input capture.",
        ],
        preconditions: &[
            Precondition { label: "Input-capture / session-replay present", engines: &["keylogger", "spyware"], keywords: &["keystroke", "session-replay", "session replay", "input capture", "keydown"], required: true },
            Precondition { label: "Missing / weak Content-Security-Policy", engines: &["xss", "csp", "header", "security_header"], keywords: &["content-security-policy", "csp", "missing csp", "unsafe-inline", "xss"], required: true },
        ],
    },
    VectorRule {
        id: "supply_chain_to_runtime",
        name: "Supply-chain compromise → CI/CD → production runtime",
        base_severity: "critical",
        novelty: 5,
        tactics: &["TA0001", "TA0003", "TA0004"],
        mitre_chain: &["T1195.001", "T1195.002", "T1072", "T1651"],
        narrative: "A vulnerable / typosquatted dependency combines with a permissive CI/CD pipeline (unpinned actions, secrets in build, no provenance). A poisoned package executes inside the build and rides the deployment path straight into the production runtime — the SolarWinds/Codecov pattern.",
        business_impact: "Attacker code executes with production privileges across every environment the pipeline deploys to; extremely hard to detect post-deploy.",
        recommended_actions: &[
            "Pin and hash-lock all dependencies and CI actions; require signed provenance (SLSA) on build artifacts.",
            "Move build secrets to short-lived OIDC tokens and forbid plaintext secrets in pipeline config.",
            "Gate deploys on SBOM diff + artifact signature verification.",
        ],
        preconditions: &[
            Precondition { label: "Supply-chain / dependency weakness", engines: &["supply_chain", "dependency", "sbom"], keywords: &["dependency", "typosquat", "malicious package", "supply chain", "outdated component"], required: true },
            Precondition { label: "CI/CD pipeline exposure", engines: &["cicd", "pipeline", "container_registry"], keywords: &["ci/cd", "pipeline", "github action", "unpinned", "secrets in build", "workflow"], required: true },
        ],
    },
    VectorRule {
        id: "leaked_secret_no_mfa_takeover",
        name: "Leaked credential + weak MFA → identity takeover",
        base_severity: "high",
        novelty: 4,
        tactics: &["TA0001", "TA0006", "TA0005"],
        mitre_chain: &["T1589.001", "T1078", "T1556.006"],
        narrative: "A credential or API key surfaced in a public leak / repo lands against an identity surface that does not enforce phishing-resistant MFA. The attacker authenticates directly as the user and, where MFA is push-based, fatigues it — no exploit required.",
        business_impact: "Direct account takeover of employee or service identities; the most common initial-access path in real incidents.",
        recommended_actions: &[
            "Rotate every exposed secret immediately and invalidate active sessions.",
            "Enforce phishing-resistant MFA (WebAuthn/FIDO2) and disable push-approval fallback.",
            "Add leaked-credential monitoring to the identity provider's risk sign-in policy.",
        ],
        preconditions: &[
            Precondition { label: "Leaked secret / credential exposure", engines: &["leak_hunter", "secret", "leak", "dark_web", "github_monitor"], keywords: &["leaked", "exposed credential", "api key", "secret found", "password dump", "paste"], required: true },
            Precondition { label: "Weak / missing MFA on identity surface", engines: &["identity", "kerberos", "saml", "oauth", "password_spray", "auth"], keywords: &["mfa", "multi-factor", "no mfa", "single factor", "weak authentication", "password spray"], required: true },
        ],
    },
    VectorRule {
        id: "external_exposure_lateral_movement",
        name: "External exposure → internal lateral movement",
        base_severity: "high",
        novelty: 3,
        tactics: &["TA0001", "TA0008"],
        mitre_chain: &["T1190", "T1133", "T1021"],
        narrative: "An externally reachable service (subdomain takeover, exposed admin panel, forgotten host) sits in front of a flat internal network with weak segmentation. A foothold on the edge service pivots laterally because internal services trust each other by network position.",
        business_impact: "A single edge foothold reaches internal crown jewels; segmentation failures turn a contained bug into a domain-wide incident.",
        recommended_actions: &[
            "Reclaim or remove the dangling / exposed edge asset.",
            "Segment internal networks and require authenticated, least-privilege service-to-service calls.",
            "Deploy east-west monitoring to detect lateral movement from edge hosts.",
        ],
        preconditions: &[
            Precondition { label: "External attack-surface exposure", engines: &["asm", "subdomain", "domain_discovery", "attack_surface"], keywords: &["subdomain takeover", "exposed", "dangling", "admin panel", "open service"], required: true },
            Precondition { label: "Weak internal segmentation / network reach", engines: &["network", "port", "smb", "lateral"], keywords: &["open port", "flat network", "segmentation", "internal service", "smb"], required: true },
        ],
    },
    VectorRule {
        id: "storage_exposure_bulk_exfil",
        name: "Misconfigured storage → bulk data exfiltration",
        base_severity: "critical",
        novelty: 3,
        tactics: &["TA0009", "TA0010"],
        mitre_chain: &["T1530", "T1567.002", "T1048"],
        narrative: "A publicly readable / writable object store (S3, blob, bucket) combines with the absence of egress controls or DLP. An attacker enumerates and pulls the entire dataset to cloud storage they control, with nothing on the path to cap the transfer.",
        business_impact: "Mass exfiltration of the exposed dataset — customer PII, backups, or secrets — often the trigger for a breach-notification obligation.",
        recommended_actions: &[
            "Make the bucket private, enable Block Public Access, and audit existing ACLs / policies.",
            "Add egress filtering / DLP so large transfers to unknown cloud endpoints are blocked and alerted.",
            "Enable object-level access logging and anomaly alerting on read volume.",
        ],
        preconditions: &[
            Precondition { label: "Publicly exposed cloud storage", engines: &["cloud", "aws", "s3", "storage"], keywords: &["public bucket", "s3", "object listing", "publicly readable", "blob container"], required: true },
            Precondition { label: "Sensitive-data / exfil path present", engines: &["data", "exfil", "dns"], keywords: &["pii", "sensitive data", "exfil", "no egress", "data exposure", "backup"], required: true },
        ],
    },
    VectorRule {
        id: "email_spoof_to_phishing",
        name: "Email spoofing + employee OSINT → targeted phishing",
        base_severity: "medium",
        novelty: 3,
        tactics: &["TA0043", "TA0001"],
        mitre_chain: &["T1589.002", "T1598", "T1566.001"],
        narrative: "Weak email authentication (missing/permissive SPF, DKIM, or DMARC p=none) lets an attacker spoof the organization's own domain. Paired with employee identities harvested via OSINT, they send internal-looking spear-phishing that lands in inboxes unflagged.",
        business_impact: "High-credibility internal phishing enabling BEC, credential theft, and initial access; direct financial-fraud exposure.",
        recommended_actions: &[
            "Publish SPF, DKIM, and DMARC with an enforcing policy (p=reject) and monitor aggregate reports.",
            "Reduce public employee-directory exposure and run targeted phishing awareness for named roles.",
            "Enable external-sender banners and impersonation protection at the mail gateway.",
        ],
        preconditions: &[
            Precondition { label: "Weak email authentication (SPF/DKIM/DMARC)", engines: &["email", "dns", "email_dns"], keywords: &["spf", "dkim", "dmarc", "p=none", "email spoof", "mail authentication"], required: true },
            Precondition { label: "Employee / identity OSINT exposure", engines: &["osint", "leak_hunter", "recon"], keywords: &["employee", "email address", "linkedin", "osint", "harvested", "staff"], required: true },
        ],
    },
    VectorRule {
        id: "tls_downgrade_session_theft",
        name: "TLS downgrade + missing HSTS → session theft",
        base_severity: "high",
        novelty: 4,
        tactics: &["TA0009", "TA0006"],
        mitre_chain: &["T1557", "T1040", "T1539"],
        narrative: "A weak transport posture (legacy TLS, downgrade-permissive ciphers) combines with a missing HSTS policy. A network-position attacker forces a plaintext/downgraded handshake and captures the session cookie, hijacking authenticated sessions without touching the application.",
        business_impact: "Session hijacking of authenticated users including admins; bypasses application-layer auth entirely.",
        recommended_actions: &[
            "Disable TLS < 1.2 and downgrade-permissive ciphers; prefer TLS 1.3.",
            "Enforce HSTS with a long max-age and preload; set Secure + SameSite on session cookies.",
            "Bind sessions to client characteristics and shorten session lifetime.",
        ],
        preconditions: &[
            Precondition { label: "Weak TLS / crypto posture", engines: &["crypto", "tls", "pki", "pqc"], keywords: &["tls 1.0", "tls 1.1", "weak cipher", "downgrade", "sslv3", "rc4"], required: true },
            Precondition { label: "Missing HSTS / transport hardening", engines: &["header", "security_header", "pki_tls"], keywords: &["hsts", "strict-transport-security", "missing hsts", "no hsts"], required: true },
        ],
    },
];

/// Minimum matched preconditions for a rule to fire. All `required` preconditions must match; this
/// is an additional floor so a rule with optional preconditions still needs genuine correlation.
const MIN_MATCHED: usize = 2;

/// Synthesize composite attack vectors from a tenant's findings.
///
/// Deterministic and evidence-gated: a rule fires only when every `required` precondition is matched
/// by at least one finding and at least [`MIN_MATCHED`] preconditions match overall. Vectors are
/// returned highest-priority first.
pub fn synthesize(findings: &[FindingLite]) -> Vec<AttackVector> {
    let mut out: Vec<AttackVector> = Vec::new();

    for rule in RULES {
        // Match each precondition to a DISTINCT finding: a real cross-domain vector must be
        // evidenced by separate signals, so one finding whose text happens to hit two patterns
        // cannot manufacture a correlation with itself. Greedy highest-severity assignment over
        // unused findings; with 2-3 preconditions this is optimal enough and fully deterministic.
        let mut matched_labels: Vec<String> = Vec::new();
        let mut evidence: Vec<&FindingLite> = Vec::new();
        let mut used: Vec<bool> = vec![false; findings.len()];
        let mut all_required_met = true;
        let mut matched_count = 0usize;

        for pc in rule.preconditions {
            let best = findings
                .iter()
                .enumerate()
                .filter(|(i, f)| !used[*i] && precondition_matches(pc, f))
                .max_by_key(|(_, f)| severity_rank(&f.severity));
            match best {
                Some((i, f)) => {
                    used[i] = true;
                    matched_count += 1;
                    matched_labels.push(pc.label.to_string());
                    evidence.push(f);
                }
                None => {
                    if pc.required {
                        all_required_met = false;
                        break;
                    }
                }
            }
        }

        if !all_required_met || matched_count < MIN_MATCHED {
            continue;
        }

        // Severity: the strongest evidence severity, floored by the rule's inherent danger. No
        // blanket escalation — a fully-corroborated chain is the normal firing case, so bumping on
        // it would make almost every vector critical and destroy the signal.
        let evidence_rank = evidence
            .iter()
            .map(|f| severity_rank(&f.severity))
            .max()
            .unwrap_or(0);
        let rank = evidence_rank.max(severity_rank(rule.base_severity));
        let severity = rank_to_severity(rank);

        let confidence = matched_count as f64 / rule.preconditions.len() as f64;
        // Priority blends how bad (severity), how sure (confidence), and how rare (novelty).
        let priority = (rank as f64) * confidence * (rule.novelty as f64) / 5.0;

        // Client scope: if every evidence finding shares a client_id, attribute the vector to it.
        let client_ids: std::collections::BTreeSet<i64> =
            evidence.iter().filter_map(|f| f.client_id).collect();
        let client_id = if client_ids.len() == 1 {
            client_ids.into_iter().next()
        } else {
            None
        };

        out.push(AttackVector {
            id: rule.id.to_string(),
            name: rule.name.to_string(),
            severity: severity.to_string(),
            confidence: (confidence * 100.0).round() / 100.0,
            novelty: rule.novelty,
            priority: (priority * 100.0).round() / 100.0,
            tactics: rule.tactics.iter().map(|s| s.to_string()).collect(),
            mitre_chain: rule.mitre_chain.iter().map(|s| s.to_string()).collect(),
            narrative: rule.narrative.to_string(),
            business_impact: rule.business_impact.to_string(),
            recommended_actions: rule
                .recommended_actions
                .iter()
                .map(|s| s.to_string())
                .collect(),
            matched_preconditions: matched_labels,
            evidence: evidence
                .iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "engine": f.engine,
                        "severity": f.severity,
                        "title": f.title,
                    })
                })
                .collect(),
            client_id,
        });
    }

    out.sort_by(|a, b| {
        b.priority
            .partial_cmp(&a.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// Serialize the synthesis result to the API envelope.
pub fn synthesize_json(findings: &[FindingLite]) -> Value {
    let vectors = synthesize(findings);
    let highest = vectors
        .iter()
        .map(|v| severity_rank(&v.severity))
        .max()
        .map(rank_to_severity)
        .unwrap_or("info");
    json!({
        "ok": true,
        "count": vectors.len(),
        "highest_severity": highest,
        "coverage": {
            "rules_total": RULES.len(),
            "findings_analyzed": findings.len(),
        },
        "vectors": vectors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, engine: &str, severity: &str, title: &str, desc: &str) -> FindingLite {
        FindingLite {
            id: id.to_string(),
            engine: engine.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            description: desc.to_string(),
            client_id: Some(1),
        }
    }

    #[test]
    fn no_correlation_no_vectors() {
        // A single lonely finding correlates with nothing.
        let findings = vec![f("1", "asm", "medium", "Open port 8080", "")];
        assert!(synthesize(&findings).is_empty());
    }

    #[test]
    fn one_finding_cannot_satisfy_two_legs() {
        // "asm" engine + "open port" text both point at the external-exposure rule's two legs, but a
        // single finding must not manufacture a correlation with itself.
        let findings = vec![f("1", "asm", "high", "Open port 8080 exposed", "open port")];
        assert!(synthesize(&findings)
            .iter()
            .all(|v| v.id != "external_exposure_lateral_movement"));
        // Add a genuinely distinct network finding and the vector should now fire.
        let mut two = findings.clone();
        two.push(f(
            "2",
            "network_scan",
            "high",
            "Flat internal network",
            "smb reachable, no segmentation",
        ));
        assert!(synthesize(&two)
            .iter()
            .any(|v| v.id == "external_exposure_lateral_movement"));
    }

    #[test]
    fn ssrf_plus_cloud_metadata_fires_imds_chain() {
        let findings = vec![
            f(
                "1",
                "ssrf_engine",
                "high",
                "SSRF in /fetch",
                "server-side request forgery",
            ),
            f(
                "2",
                "aws_attack_engine",
                "medium",
                "Cloud metadata reachable",
                "instance metadata 169.254 exposed",
            ),
        ];
        let v = synthesize(&findings);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "cloud_imds_credential_theft");
        // both preconditions met -> confidence 1.0; severity is the rule's inherent critical floor
        assert!((v[0].confidence - 1.0).abs() < f64::EPSILON);
        assert_eq!(v[0].severity, "critical");
        assert_eq!(v[0].mitre_chain, vec!["T1190", "T1552.005", "T1078.004"]);
        assert_eq!(v[0].evidence.len(), 2);
        assert_eq!(v[0].client_id, Some(1));
    }

    #[test]
    fn required_precondition_missing_does_not_fire() {
        // SSRF alone (no cloud metadata) must not synthesize the IMDS chain.
        let findings = vec![f(
            "1",
            "ssrf_engine",
            "high",
            "SSRF",
            "server-side request forgery",
        )];
        assert!(synthesize(&findings)
            .iter()
            .all(|v| v.id != "cloud_imds_credential_theft"));
    }

    #[test]
    fn keyword_matching_works_without_exact_engine_id() {
        // Match the CSP leg by description keyword even though the engine id is generic.
        let findings = vec![
            f(
                "1",
                "keylogger_engine",
                "low",
                "Session-replay SDK",
                "hotjar session replay present",
            ),
            f(
                "2",
                "web_scan",
                "medium",
                "Header check",
                "missing content-security-policy header",
            ),
        ];
        let v = synthesize(&findings);
        assert!(v.iter().any(|x| x.id == "client_side_credential_capture"));
    }

    #[test]
    fn vectors_sorted_by_priority_desc() {
        let findings = vec![
            // supply-chain (critical, novelty 5) + cicd -> high priority
            f(
                "1",
                "supply_chain_scanner",
                "high",
                "Vulnerable dependency",
                "outdated component",
            ),
            f(
                "2",
                "cicd_pipeline_engine",
                "high",
                "Unpinned action",
                "github action pipeline unpinned",
            ),
            // email spoof (medium, novelty 3) -> lower priority
            f(
                "3",
                "email_dns_posture",
                "medium",
                "DMARC p=none",
                "dmarc p=none spf",
            ),
            f(
                "4",
                "osint_engine",
                "low",
                "Employee emails",
                "employee email address harvested via osint",
            ),
        ];
        let v = synthesize(&findings);
        assert!(v.len() >= 2);
        for w in v.windows(2) {
            assert!(w[0].priority >= w[1].priority);
        }
        assert_eq!(v[0].id, "supply_chain_to_runtime");
    }

    #[test]
    fn json_envelope_reports_counts_and_highest_severity() {
        let findings = vec![
            f(
                "1",
                "ssrf_engine",
                "high",
                "SSRF",
                "server-side request forgery",
            ),
            f(
                "2",
                "aws_attack_engine",
                "high",
                "IMDS",
                "instance metadata 169.254",
            ),
        ];
        let out = synthesize_json(&findings);
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["count"], json!(1));
        assert_eq!(out["highest_severity"], json!("critical"));
        assert_eq!(out["coverage"]["findings_analyzed"], json!(2));
    }
}
