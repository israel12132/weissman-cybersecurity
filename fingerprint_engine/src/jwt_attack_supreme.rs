//! Supreme-tier JWT attack synthesis — toxic combos, security graph, agent guidance.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use serde_json::{json, Value};

const ENGINE_ID: &str = "jwt_attack";
const MITRE: &str = "T1550.001";

#[derive(Default)]
pub struct JwtSignals {
    pub token_count: usize,
    pub alg_none_accepted: bool,
    pub alg_none_in_use: bool,
    pub confusion_accepted: bool,
    pub weak_hmac_cracked: bool,
    pub kid_surface: bool,
    pub jku_x5u_surface: bool,
    pub weak_jwks: bool,
    pub privilege_claims: bool,
    pub long_lifetime: bool,
}

pub fn collect_signals(findings: &[Value], token_count: usize) -> JwtSignals {
    let mut sig = JwtSignals { token_count, ..Default::default() };
    for f in findings {
        let title = f.get("title").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
        let ev_attack = f
            .get("evidence")
            .and_then(|e| e.get("attack"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if title.contains("alg=none") && title.contains("accepted") {
            sig.alg_none_accepted = true;
        }
        if title.contains("alg=none") && title.contains("in use") {
            sig.alg_none_in_use = true;
        }
        if title.contains("algorithm-confusion") || ev_attack == "rs256_to_hs256_confusion" {
            sig.confusion_accepted = true;
        }
        if title.contains("weak hmac") || title.contains("hmac secret") || title.contains("cracked") {
            sig.weak_hmac_cracked = true;
        }
        if title.contains("'kid'") || title.contains("kid header") {
            sig.kid_surface = true;
        }
        if title.contains("jku") || title.contains("x5u") {
            sig.jku_x5u_surface = true;
        }
        if title.contains("jwks") && (title.contains("weak") || title.contains("private")) {
            sig.weak_jwks = true;
        }
        if title.contains("privilege") || title.contains("admin") && title.contains("claim") {
            sig.privilege_claims = true;
        }
        if title.contains("lifetime") || title.contains("no exp") || title.contains("long-lived") {
            sig.long_lifetime = true;
        }
    }
    sig
}

pub struct JwtCategoryScores {
    pub signature_integrity: f64,
    pub algorithm_policy: f64,
    pub key_hygiene: f64,
    pub header_injection: f64,
    pub claim_hygiene: f64,
    pub jwks_posture: f64,
    pub token_lifetime: f64,
    pub harvest_surface: f64,
}

impl JwtCategoryScores {
    fn from_signals(sig: &JwtSignals) -> Self {
        let bad = |b: bool, w: f64| -> f64 { if b { 100.0 - w } else { 100.0 } };
        Self {
            signature_integrity: bad(sig.alg_none_accepted || sig.confusion_accepted || sig.weak_hmac_cracked, 45.0),
            algorithm_policy: bad(sig.alg_none_in_use || sig.alg_none_accepted, 50.0),
            key_hygiene: bad(sig.weak_jwks || sig.weak_hmac_cracked, 40.0),
            header_injection: bad(sig.kid_surface || sig.jku_x5u_surface, 35.0),
            claim_hygiene: bad(sig.privilege_claims, 25.0),
            jwks_posture: bad(sig.weak_jwks, 30.0),
            token_lifetime: bad(sig.long_lifetime, 20.0),
            harvest_surface: if sig.token_count == 0 { 70.0 } else { 100.0 },
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "signature_integrity": self.signature_integrity.round() as u32,
            "algorithm_policy": self.algorithm_policy.round() as u32,
            "key_hygiene": self.key_hygiene.round() as u32,
            "header_injection": self.header_injection.round() as u32,
            "claim_hygiene": self.claim_hygiene.round() as u32,
            "jwks_posture": self.jwks_posture.round() as u32,
            "token_lifetime": self.token_lifetime.round() as u32,
            "harvest_surface": self.harvest_surface.round() as u32,
        })
    }
}

pub fn finalize_category_scores(sig: &JwtSignals) -> JwtCategoryScores {
    JwtCategoryScores::from_signals(sig)
}

pub fn extend_attack_paths(target: &str, sig: &JwtSignals, findings: &mut Vec<Value>) {
    if sig.confusion_accepted && sig.privilege_claims {
        push_path(
            findings,
            "Attack path: algorithm confusion → privilege claim escalation → admin API",
            "critical",
            &[
                "Forge HS256 token with RSA public key as secret",
                "Embed admin/root claims from harvested token",
                "Call privileged API endpoints",
                "Operate as highest-privilege user",
            ],
            target,
            0.94,
        );
    }
    if sig.kid_surface && sig.jku_x5u_surface {
        push_path(
            findings,
            "Attack path: kid traversal + jku SSRF → attacker-controlled signing key",
            "critical",
            &[
                "Supply malicious jku URL pointing to attacker JWKS",
                "Or kid path traversal to load unexpected key file",
                "Forge tokens signed with attacker key",
                "Bypass all JWT verification",
            ],
            target,
            0.9,
        );
    }
    if sig.weak_hmac_cracked && sig.long_lifetime {
        push_path(
            findings,
            "Attack path: cracked HMAC secret → long-lived token persistence",
            "high",
            &[
                "Offline crack JWT HMAC with wordlist",
                "Mint arbitrary claims with cracked secret",
                "Long exp maximizes persistence window",
                "Maintain access until secret rotation",
            ],
            target,
            0.88,
        );
    }
}

fn push_path(findings: &mut Vec<Value>, title: &str, sev: &str, steps: &[&str], target: &str, conf: f64) {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        sev,
        MITRE,
        "Correlated JWT weaknesses form a complete authentication-bypass chain.",
        target,
        conf,
        Evidence::new().with("steps", json!(steps)),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("attack_path"));
        o.insert("attack_path".to_string(), json!(steps));
    }
    findings.push(f);
}

pub fn emit_toxic_headline(target: &str, sig: &JwtSignals, findings: &mut Vec<Value>) {
    let mut combos = Vec::new();
    if sig.alg_none_accepted {
        combos.push("alg=none accepted ⇒ unsigned token auth bypass");
    }
    if sig.confusion_accepted {
        combos.push("RS256→HS256 confusion accepted ⇒ forge any identity");
    }
    if sig.weak_hmac_cracked {
        combos.push("weak HMAC secret cracked ⇒ offline token minting");
    }
    if sig.confusion_accepted && sig.privilege_claims {
        combos.push("algorithm confusion + privilege claims ⇒ instant admin takeover");
    }
    if sig.kid_surface && sig.jku_x5u_surface {
        combos.push("kid + jku/x5u surface ⇒ attacker-controlled verification key");
    }
    if sig.alg_none_accepted && sig.long_lifetime {
        combos.push("alg=none + long-lived token ⇒ permanent ghost session");
    }
    if combos.is_empty() {
        return;
    }
    let headline = combos.join(" ⊕ ");
    let mut f = finding_rich(
        ENGINE_ID,
        &format!("TOXIC COMBINATION: {headline}"),
        "critical",
        MITRE,
        "Correlated JWT verification failures enable full authentication bypass — rotate keys and enforce algorithm allow-lists immediately.",
        target,
        0.97,
        Evidence::new()
            .with("combinations", json!(combos))
            .with("toxic_count", combos.len())
            .with("tokens_analyzed", sig.token_count),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("toxic_combination"));
    }
    findings.insert(0, f);
}

pub fn emit_remediation_roadmap(target: &str, sig: &JwtSignals, findings: &mut Vec<Value>) {
    let mut steps: Vec<Value> = Vec::new();
    let mut n = 1u8;
    let mut push = |tier: &str, action: &str, detail: &str| {
        steps.push(json!({ "priority": n, "tier": tier, "action": action, "detail": detail }));
        n += 1;
    };
    if sig.alg_none_accepted || sig.alg_none_in_use {
        push("P0", "Reject alg=none", "Hard-deny unsigned JWTs; allow-list RS256/ES256 only");
    }
    if sig.confusion_accepted {
        push("P0", "Pin expected algorithm", "Verify alg matches key type; never use key bytes as HMAC secret");
    }
    if sig.weak_hmac_cracked {
        push("P0", "Rotate HMAC secret", "Deploy 256+ bit random secret; invalidate all outstanding tokens");
    }
    if sig.kid_surface || sig.jku_x5u_surface {
        push("P0", "Allow-list kid/jku", "Never fetch keys from jku/x5u; map kid to internal key store only");
    }
    if sig.weak_jwks {
        push("P1", "Harden JWKS", "RSA ≥2048; never expose private keys; rotate kid on schedule");
    }
    if sig.long_lifetime {
        push("P1", "Shorten token TTL", "Access tokens ≤15m; refresh rotation; enforce exp server-side");
    }
    push("P2", "Deploy Weissman agent for token replay analytics", "Detect forged-token usage across microservices");
    if steps.is_empty() {
        return;
    }
    let mut f = finding_rich(
        ENGINE_ID,
        "Prioritized JWT remediation roadmap",
        "info",
        MITRE,
        "Ordered JWT hardening plan from observed verification gaps.",
        target,
        0.99,
        Evidence::new()
            .with("roadmap", Value::Array(steps))
            .with("category_scores", finalize_category_scores(sig).to_json()),
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("remediation_roadmap"));
    }
    findings.push(f);
}

pub fn emit_agent_guidance(target: &str, findings: &mut Vec<Value>) {
    for (cap, desc) in [
        ("token_replay_mesh", "Cross-service JWT replay detection across internal APIs"),
        ("refresh_token_rotation", "Refresh-token family binding and reuse detection"),
        ("asymmetric_key_dpapi", "On-host private key storage audit (DPAPI/HSM)"),
        ("claim_level_authz", "Server-side authorization matrix vs token claims diff"),
    ] {
        let mut f = finding_rich(
            ENGINE_ID,
            &format!("Agent-required: {desc}"),
            "info",
            MITRE,
            &format!("Capability `{cap}` requires Weissman host agent — not fully observable via external JWT lab alone."),
            target,
            1.0,
            Evidence::new().with("capability", cap).with("requires_agent", true),
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("agent_guidance"));
        }
        findings.push(f);
    }
}

pub fn build_security_graph(target: &str, sig: &JwtSignals, host: &str) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let score = finalize_category_scores(sig);
    let avg = (score.signature_integrity + score.algorithm_policy + score.key_hygiene) / 3.0;
    let mut nodes = vec![GraphNode {
        id: "root".to_string(),
        label: if host.is_empty() { target.to_string() } else { host.to_string() },
        node_type: "root".to_string(),
        status: if avg >= 80.0 { "secure".into() } else if avg >= 50.0 { "degraded".into() } else { "exposed".into() },
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    let mut add = |id: &str, label: &str, kind: &str| {
        nodes.push(GraphNode {
            id: id.into(),
            label: label.into(),
            node_type: "jwt_surface".into(),
            status: "exposed".into(),
            cname_target: None,
            raw_finding: None,
        });
        edges.push(GraphEdge {
            id: format!("e_root_{id}"),
            from_id: "root".into(),
            to_id: id.into(),
            edge_type: kind.into(),
        });
    };
    if sig.token_count > 0 {
        add("tokens", &format!("{} JWT(s) harvested", sig.token_count), "TOKEN_HARVEST");
    }
    if sig.alg_none_accepted {
        add("none", "alg=none accepted", "ALG_NONE");
    }
    if sig.confusion_accepted {
        add("confusion", "RS256→HS256 confusion", "ALG_CONFUSION");
    }
    if sig.weak_hmac_cracked {
        add("hmac", "Weak HMAC cracked", "WEAK_HMAC");
    }
    if sig.kid_surface || sig.jku_x5u_surface {
        add("header", "kid/jku injection surface", "HEADER_INJECT");
    }
    if sig.confusion_accepted && sig.privilege_claims {
        edges.push(GraphEdge {
            id: "ap_admin".into(),
            from_id: "confusion".into(),
            to_id: "tokens".into(),
            edge_type: "ADMIN_FORGE".into(),
        });
    }
    let _ = target;
    (nodes, edges)
}
