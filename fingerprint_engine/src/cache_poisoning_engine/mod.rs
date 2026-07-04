//! Web Cache Poisoning & Deception Posture — agentless, real-probe only.
#![allow(clippy::pedantic, clippy::nursery, clippy::too_many_lines)]

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{header_value, http_get_with_headers, HttpProbe};
use crate::engine_result::{print_result, EngineResult};
use futures::future::join_all;
use reqwest::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

include!("inc/util.inc.rs");
include!("inc/probes.inc.rs");
include!("inc/analysis.inc.rs");
include!("inc/runner.inc.rs");
#[cfg(test)]
mod tests {
    use super::*;

    fn probe(headers: Vec<(&str, &str)>, body: &str) -> HttpProbe {
        HttpProbe {
            status: 200,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            final_url: "https://x.test/".to_string(),
        }
    }

    #[test]
    fn with_buster_handles_query() {
        assert_eq!(
            with_buster("https://x.test/", "ab"),
            "https://x.test/?wzcb=ab"
        );
        assert_eq!(
            with_buster("https://x.test/?a=1", "ab"),
            "https://x.test/?a=1&wzcb=ab"
        );
    }

    #[test]
    fn detect_cache_identifies_vendor_and_hit() {
        let s = detect_cache(&probe(vec![("CF-Cache-Status", "HIT"), ("Age", "42")], ""));
        assert!(s.cacheable && s.hit);
        assert_eq!(s.vendor.as_deref(), Some("Cloudflare"));
        let miss = detect_cache(&probe(vec![("Content-Type", "text/html")], ""));
        assert!(!miss.cacheable && !miss.hit);
    }

    #[test]
    fn reflects_finds_canary_in_body_and_location() {
        let b = probe(vec![("Content-Type", "text/html")], "<a>wzc123</a>");
        assert_eq!(reflects(&b, "wzc123"), Some("body"));
        let l = probe(vec![("Location", "https://wzc999.poison.example/")], "");
        assert_eq!(reflects(&l, "wzc999"), Some("Location header"));
        assert!(reflects(&b, "absent").is_none());
    }

    #[test]
    fn header_value_for_kinds() {
        assert!(
            header_value_for(HeaderKind::Host, "wzcabcd", DEFAULT_POISON_DOMAIN)
                .ends_with(".poison.example")
        );
        assert!(
            header_value_for(HeaderKind::Path, "wzcabcd", DEFAULT_POISON_DOMAIN).starts_with('/')
        );
        assert!(
            header_value_for(HeaderKind::Language, "wzcabcd", DEFAULT_POISON_DOMAIN)
                .contains("wzcabcd")
        );
    }

    #[test]
    fn sanitize_canary_domain_rejects_invalid() {
        assert_eq!(sanitize_canary_domain("evil.test"), "evil.test");
        assert_eq!(sanitize_canary_domain("https://bad"), DEFAULT_POISON_DOMAIN);
    }

    #[test]
    fn build_coverage_manifest_world_class_when_full() {
        let flags: Vec<(&str, bool)> = (0..51).map(|_| ("probe", true)).collect();
        let m = build_coverage_manifest(&flags, 3);
        assert_eq!(
            m.get("competitive_parity").and_then(Value::as_str),
            Some("world_class_complete")
        );
        assert_eq!(
            m.get("sealed_complete").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn is_publicly_cacheable_detects_public() {
        assert!(is_publicly_cacheable("public, max-age=3600"));
        assert!(!is_publicly_cacheable("private, no-store"));
    }

    #[test]
    fn body_sha256_stable() {
        assert_eq!(body_sha256("abc"), body_sha256("abc"));
        assert_ne!(body_sha256("abc"), body_sha256("abd"));
    }

    #[test]
    fn severity_rank_orders() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("medium") > severity_rank("low"));
    }

    #[test]
    fn normalization_variants_includes_baseline_and_alts() {
        let v = normalization_variants("https://x.test/account", "abc123");
        assert!(v.iter().any(|(_, l)| *l == "baseline"));
        assert!(v.len() >= 2);
        assert!(v[0].0.contains("wzcb=abc123"));
    }

    #[test]
    fn content_length_parses() {
        let p = probe(vec![("Content-Length", "1234")], "");
        assert_eq!(content_length(&p), Some(1234));
    }

    #[test]
    fn with_pad_param_appends() {
        let u = with_buster("https://x.test/a", "cb1");
        assert_eq!(with_pad_param(&u, "alpha"), format!("{}&wkpad=alpha", u));
    }

    #[test]
    fn compute_posture_dimensions_penalizes_critical() {
        let f = cache_finding(
            "t",
            "x",
            "critical",
            "d",
            0.9,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let dims = compute_posture_dimensions(&[f]);
        assert!(
            dims.get("unkeyed_inputs")
                .and_then(Value::as_u64)
                .unwrap_or(100)
                < 100
        );
    }

    #[test]
    fn is_redirect_status_detects_3xx() {
        assert!(is_redirect_status(302));
        assert!(!is_redirect_status(200));
    }

    #[test]
    fn cache_control_schism_detects_edge_override() {
        assert!(cache_control_schism("no-store", "public, s-maxage=3600"));
        assert!(!cache_control_schism("public", "public"));
    }

    #[test]
    fn build_attack_chains_on_confirmed_poison() {
        let f = cache_finding(
            "t",
            "poison",
            "critical",
            "d",
            0.95,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let chains = build_attack_chains(&[f], true);
        assert!(!chains.is_empty());
    }

    #[test]
    fn compute_exploitability_index_weights_confirmed() {
        let f = cache_finding(
            "t",
            "x",
            "critical",
            "d",
            0.95,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        assert!(compute_exploitability_index(&[f]) >= 28);
    }

    #[test]
    fn discover_paths_from_html_finds_hrefs() {
        let body = r#"<a href="/account">x</a><a href="/api/v1">y</a>"#;
        let p = discover_paths_from_html(body);
        assert!(p.contains(&"/account".to_string()));
    }

    #[test]
    fn compute_beyond_score_takes_min() {
        assert_eq!(compute_beyond_score(80, 30, &json!({"a": 60})), 60);
    }

    #[test]
    fn normalization_variants_includes_null_byte() {
        let v = normalization_variants("https://x.test/account", "abc123");
        assert!(v.iter().any(|(_, l)| *l == "null_byte"));
        assert!(v.iter().any(|(_, l)| *l == "double_encoded_null"));
    }

    #[test]
    fn build_risk_matrix_aggregates_by_category() {
        let f = cache_finding(
            "t",
            "x",
            "high",
            "d",
            0.9,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let m = build_risk_matrix(&[f]);
        assert_eq!(
            m.get("cache_poisoning")
                .and_then(|v| v.get("high"))
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn build_cdn_playbook_includes_urgent_on_confirmed() {
        let f = cache_finding(
            "t",
            "x",
            "critical",
            "d",
            0.95,
            "cache_poisoning",
            "confirmed",
            "r",
            Evidence::new(),
        );
        let pb = build_cdn_playbook(Some("Cloudflare"), &[f]);
        let steps = pb.get("steps").and_then(Value::as_array).unwrap();
        assert!(steps[0].as_str().unwrap().contains("URGENT"));
    }

    #[test]
    fn dedupe_findings_removes_duplicates() {
        let ev = Evidence::new().with("url", "https://x.test/");
        let a = cache_finding(
            "t",
            "same title",
            "high",
            "d",
            0.8,
            "cache_poisoning",
            "reflected",
            "r",
            ev.clone(),
        );
        let b = cache_finding(
            "t",
            "same title",
            "high",
            "d",
            0.8,
            "cache_poisoning",
            "reflected",
            "r",
            ev,
        );
        let out = dedupe_findings(vec![a, b]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn compute_poison_window_seconds_max_from_evidence() {
        let ev = Evidence::new().with("cache_ttl_seconds", json!(7200));
        let f = cache_finding(
            "t",
            "x",
            "info",
            "d",
            0.5,
            "cache_fingerprint",
            "present",
            "r",
            ev,
        );
        assert_eq!(compute_poison_window_seconds(&[f]), 7200);
    }

    #[test]
    fn parse_cache_ttl_seconds_reads_max_age() {
        assert_eq!(parse_cache_ttl_seconds("public, max-age=3600"), Some(3600));
        assert_eq!(
            parse_cache_ttl_seconds("s-maxage=86400, max-age=0"),
            Some(86400)
        );
    }

    #[test]
    fn s_maxage_browser_schism_detects_conflict() {
        assert!(s_maxage_browser_schism("max-age=0, s-maxage=3600"));
        assert!(!s_maxage_browser_schism("public, max-age=3600"));
    }

    #[test]
    fn parse_url_host_extracts_authority() {
        assert_eq!(
            parse_url_host("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_url_host("http://cdn.test:8080/x"),
            Some("cdn.test".to_string())
        );
    }

    #[test]
    fn poc_curl_includes_url() {
        assert!(poc_curl("GET", "https://x.test/", &[], None).contains("https://x.test/"));
    }
}
