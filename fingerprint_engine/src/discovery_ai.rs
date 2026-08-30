//! Live LLM generation of HTTP paths and DNS subdomain prefixes.
//!
//! Proposals are parsed strictly (one token per line) and persisted into
//! `intel.discovery_knowledge` so the next scan never starts from zero.

use std::collections::HashSet;
use weissman_engines::discovery_corpus::{normalize_http_path, normalize_subdomain_prefix};
use weissman_engines::openai_chat::{self, DEFAULT_LLM_BASE_URL};

const LLM_TIMEOUT_SECS: u64 = 45;
const MAX_COMPLETION_TOKENS: u32 = 4096;
/// Waves per scan. Each wave conditions on newly observed tokens. No corpus cap.
const DEFAULT_WAVES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    Path,
    SubdomainPrefix,
}

impl SurfaceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::SubdomainPrefix => "subdomain_prefix",
        }
    }
}

/// Parse LLM stdout into normalized tokens. Public for unit tests.
#[must_use]
pub fn parse_generated_lines(kind: SurfaceKind, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let mut line = line.trim();
        for prefix in ["- ", "* ", "• ", "– "] {
            if let Some(rest) = line.strip_prefix(prefix) {
                line = rest.trim();
            }
        }
        if let Some((idx, ch)) = line.char_indices().find(|(_, c)| *c == '.' || *c == ')') {
            if line[..idx].chars().all(|c| c.is_ascii_digit()) && (ch == '.' || ch == ')') {
                line = line[idx + ch.len_utf8()..].trim();
            }
        }
        let parsed = match kind {
            SurfaceKind::Path => normalize_http_path(line),
            SurfaceKind::SubdomainPrefix => normalize_subdomain_prefix(line),
        };
        if let Some(v) = parsed {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

fn prompt_for(kind: SurfaceKind, target_hint: &str, tech_hint: &str, already: &[String]) -> String {
    let sample: String = already
        .iter()
        .take(80)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    match kind {
        SurfaceKind::Path => format!(
            r#"You are helping an authorized attack-surface mapper.
Target: {target_hint}
Tech hints: {tech_hint}

Already-known HTTP paths (do NOT repeat these):
{sample}

Output as many additional HTTP paths as you can that likely exist on this class of application.
Cover: admin/debug/backup/internal/graphql/swagger/actuator/well-known/identity/CI/observability/CMS/cloud/k8s/versioned REST resources, and naming-convention siblings of the known paths (v1→v2, users→users/me, auth→oauth).
Rules:
- One path per line, each starting with /
- No prose, no markdown, no numbering
- No query strings
- Invent realistic org-specific paths from the target hostname tokens when useful
"#
        ),
        SurfaceKind::SubdomainPrefix => format!(
            r#"You are helping an authorized attack-surface mapper.
Registrable domain / org: {target_hint}
Tech hints: {tech_hint}

Already-known DNS prefixes (do NOT repeat these):
{sample}

Output as many additional DNS subdomain PREFIXES as you can (the label before the registrable domain).
Cover: env×service (staging-api, prod-vpn), identity (okta, adfs, autodiscover), devops (argocd, vault, grafana), numbered (api3), geo (eu-api), shadow-IT, vendor SaaS, OT/IoT.
Rules:
- One prefix per line, lowercase, no trailing domain
- Examples of valid lines: api, staging-app, vpn-us
- No prose, no markdown, no numbering, no full FQDNs
"#
        ),
    }
}

/// One LLM round. Returns [] if the model is unreachable (scan continues on seed+DB).
pub async fn generate_round(
    kind: SurfaceKind,
    target_hint: &str,
    tech_hint: &str,
    already: &[String],
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<String> {
    let base = if llm_base.trim().is_empty() {
        DEFAULT_LLM_BASE_URL
    } else {
        llm_base.trim()
    };
    let prompt = prompt_for(kind, target_hint, tech_hint, already);
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(llm_model);
    let op = match kind {
        SurfaceKind::Path => "discovery_ai_paths",
        SurfaceKind::SubdomainPrefix => "discovery_ai_subdomains",
    };
    let text = match openai_chat::chat_completion_text(
        &client,
        base,
        &model,
        Some("You output only the requested tokens, one per line. No explanations."),
        &prompt,
        0.7,
        MAX_COMPLETION_TOKENS,
        llm_tenant_id,
        op,
        true,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    parse_generated_lines(kind, &text)
}

/// Operator kill-switch. Default on. `WEISSMAN_LIVE_AI_DISCOVERY=0` skips LLM waves
/// (seed + stored corpus still apply).
#[must_use]
pub fn live_ai_enabled() -> bool {
    match std::env::var("WEISSMAN_LIVE_AI_DISCOVERY") {
        Ok(v) => {
            let l = v.trim().to_ascii_lowercase();
            l != "0" && l != "false" && l != "no" && l != "off"
        }
        Err(_) => true,
    }
}

/// Multi-wave generation. Each wave sees tokens produced so far. Persist every proposal.
pub async fn generate_and_remember(
    pool: Option<&sqlx::PgPool>,
    kind: SurfaceKind,
    target_hint: &str,
    tech_hint: &str,
    already: &[String],
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
    waves: Option<usize>,
) -> Vec<String> {
    if !live_ai_enabled() {
        return vec![];
    }
    let waves = waves.unwrap_or(DEFAULT_WAVES).max(1);
    let mut known: Vec<String> = already.to_vec();
    let mut produced = Vec::new();
    let mut seen: HashSet<String> = known.iter().cloned().collect();
    for _ in 0..waves {
        let batch = generate_round(
            kind,
            target_hint,
            tech_hint,
            &known,
            llm_base,
            llm_model,
            llm_tenant_id,
        )
        .await;
        if batch.is_empty() {
            break;
        }
        let mut fresh = Vec::new();
        for v in batch {
            if seen.insert(v.clone()) {
                fresh.push(v);
            }
        }
        if fresh.is_empty() {
            break;
        }
        if let Some(pool) = pool {
            crate::discovery_knowledge::remember(
                pool,
                kind.as_str(),
                &fresh,
                "llm",
                false,
                tech_hint,
            )
            .await;
        }
        produced.extend(fresh.iter().cloned());
        known.extend(fresh);
    }
    produced
}

/// Seed ∪ DB ∪ extra ∪ live LLM paths. The returned set is the full unbounded corpus for this scan.
pub async fn hydrate_paths(
    pool: Option<&sqlx::PgPool>,
    target_hint: &str,
    tech_hint: &str,
    extra: &[String],
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<String> {
    let seed = weissman_engines::discovery_corpus::all_http_paths().to_vec();
    let mut stored_all = Vec::new();
    let mut stored_learned = Vec::new();
    if let Some(p) = pool {
        crate::discovery_knowledge::seed_public_knowledge(p).await;
        stored_all = crate::discovery_knowledge::load_paths(p).await;
        stored_learned = crate::discovery_knowledge::load_learned_paths(p).await;
    }
    // LLM sees the public seed so it does not reinvent /graphql; the return set is
    // learned + live proposals only (engines that need the full seed call all_http_paths).
    let known = crate::discovery_knowledge::merge_unique(&[&seed, &stored_all, extra]);
    let ai = generate_and_remember(
        pool,
        SurfaceKind::Path,
        target_hint,
        tech_hint,
        &known,
        llm_base,
        llm_model,
        llm_tenant_id,
        Some(3),
    )
    .await;
    crate::discovery_knowledge::merge_unique(&[&stored_learned, extra, &ai])
}

/// Seed ∪ DB ∪ extra ∪ live LLM subdomain prefixes.
pub async fn hydrate_subdomain_prefixes(
    pool: Option<&sqlx::PgPool>,
    target_hint: &str,
    tech_hint: &str,
    extra: &[String],
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<String> {
    let seed = weissman_engines::discovery_corpus::all_subdomain_prefixes().to_vec();
    let mut stored = Vec::new();
    if let Some(p) = pool {
        crate::discovery_knowledge::seed_public_knowledge(p).await;
        stored = crate::discovery_knowledge::load_subdomain_prefixes(p).await;
    }
    let merged = crate::discovery_knowledge::merge_unique(&[&seed, &stored, extra]);
    let ai = generate_and_remember(
        pool,
        SurfaceKind::SubdomainPrefix,
        target_hint,
        tech_hint,
        &merged,
        llm_base,
        llm_model,
        llm_tenant_id,
        Some(3),
    )
    .await;
    crate::discovery_knowledge::merge_unique(&[&merged, &ai])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_paths_from_messy_llm() {
        let raw = "1. /api/v3/admin\n- /graphql/console\nnot a path\nhttps://x.test/secret\n/ok\n";
        let out = parse_generated_lines(SurfaceKind::Path, raw);
        assert!(out.iter().any(|p| p == "/api/v3/admin"));
        assert!(out.iter().any(|p| p == "/graphql/console"));
        assert!(out.iter().any(|p| p == "/ok" || p == "/secret"));
    }

    #[test]
    fn parse_subdomain_prefixes() {
        let raw = "staging-api\nVPN-US\nhttps://evil\nwww.example.com\nokta\n";
        let out = parse_generated_lines(SurfaceKind::SubdomainPrefix, raw);
        assert!(out.contains(&"staging-api".to_string()));
        assert!(out.contains(&"vpn-us".to_string()));
        assert!(out.contains(&"okta".to_string()));
        assert!(!out.iter().any(|s| s.contains("https")));
        assert!(!out.iter().any(|s| s.contains("example.com")));
    }
}
