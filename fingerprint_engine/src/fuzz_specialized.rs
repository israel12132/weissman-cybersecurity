//! Staged live HTTP probes for XSS, CSRF, race, and open-redirect campaigns.
//!
//! These are **defensive platform probes** against the operator-authorized target: unique canaries,
//! form/cookie inspection, concurrent identical requests, and redirect-parameter Location checks.
//! They record HTTP proof (status, excerpt, Location). They do not ship exploit PoCs against
//! third parties.

use crate::fuzz_campaign::FuzzCampaignCtl;
use fuzz_core::{append_query_param, ValidatedAnomaly, XSS_REFLECTION_TOKEN};
use reqwest::redirect::Policy;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Canary host used only as a redirect destination marker. Never resolved; we inspect `Location`.
pub const REDIRECT_CANARY_HOST: &str = "weissman-open-redirect.test";

const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "returnUrl",
    "return_to",
    "dest",
    "destination",
    "continue",
    "goto",
    "callback",
    "target",
];

const XSS_PARAMS: &[&str] = &[
    "q", "query", "search", "s", "keyword", "name", "comment", "message", "callback", "title",
];

fn probe_timeout() -> Duration {
    Duration::from_secs(8)
}

fn connect_timeout() -> Duration {
    Duration::from_secs(4)
}

fn probe_client(follow_redirects: bool) -> Result<reqwest::Client, reqwest::Error> {
    let mut b = reqwest::Client::builder()
        .timeout(probe_timeout())
        .connect_timeout(connect_timeout())
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent(crate::fuzz_http_pool::random_fuzz_user_agent());
    b = if follow_redirects {
        b.redirect(Policy::limited(4))
    } else {
        b.redirect(Policy::none())
    };
    b.build()
}

fn excerpt(body: &str) -> String {
    body.chars().take(1500).collect()
}

fn looks_like_form(html: &str) -> bool {
    html.to_ascii_lowercase().contains("<form")
}

fn form_has_csrf_token(html: &str) -> bool {
    let l = html.to_ascii_lowercase();
    l.contains("name=\"csrf")
        || l.contains("name='csrf")
        || l.contains("name=\"_token")
        || l.contains("name='_token")
        || l.contains("name=\"authenticity_token")
        || l.contains("csrfmiddlewaretoken")
        || l.contains("name=\"nonce")
        || l.contains("data-csrf")
}

fn cookie_samesite_weak(set_cookie: &str) -> bool {
    let l = set_cookie.to_ascii_lowercase();
    if !l.contains("session") && !l.contains("auth") && !l.contains("sid") && !l.contains("token") {
        return false;
    }
    !l.contains("samesite=strict") && !l.contains("samesite=lax")
}

fn host_of(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .trim()
        .to_ascii_lowercase()
}

fn location_points_at_canary(location: &str) -> bool {
    location.to_ascii_lowercase().contains(REDIRECT_CANARY_HOST)
}

fn xss_unescaped(body: &str) -> bool {
    if !body.contains(XSS_REFLECTION_TOKEN) {
        return false;
    }
    // Token present as-is AND a raw tag opener from the probe survived (not HTML-escaped).
    let raw_tag = body.contains("<svg") || body.contains("<script") || body.contains("<img");
    raw_tag
        && !body.contains("&lt;svg")
        && !body.contains("&lt;script")
        && !body.contains("&lt;img")
}

/// Surface GET — records reachability so an empty campaign is never "we did nothing".
pub async fn probe_surface(target: &str, ctl: &FuzzCampaignCtl) -> Option<SurfaceSnap> {
    ctl.add_stage("surface");
    ctl.add_coverage("surface_get");
    let client = probe_client(true).ok()?;
    let start = Instant::now();
    ctl.note_probe(target);
    let resp = client.get(target).send().await.ok()?;
    let status = resp.status().as_u16();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    Some(SurfaceSnap {
        status,
        body,
        cookies,
        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
    })
}

#[derive(Clone, Debug)]
pub struct SurfaceSnap {
    pub status: u16,
    pub body: String,
    pub cookies: Vec<String>,
    pub latency_ms: f64,
}

pub async fn probe_xss(target: &str, ctl: &FuzzCampaignCtl) -> Vec<ValidatedAnomaly> {
    ctl.add_stage("xss");
    ctl.add_coverage("reflected_xss_canary");
    let Ok(client) = probe_client(true) else {
        return Vec::new();
    };
    let payloads = [
        format!("<svg/onload=alert('{}')>", XSS_REFLECTION_TOKEN),
        format!("\"'><img src=x onerror=alert('{}')>", XSS_REFLECTION_TOKEN),
        XSS_REFLECTION_TOKEN.to_string(),
    ];
    let mut out = Vec::new();
    for param in XSS_PARAMS {
        if ctl.expired() {
            break;
        }
        for payload in &payloads {
            if ctl.expired() {
                break;
            }
            let url = append_query_param(target, param, payload);
            ctl.note_probe(&url);
            let start = Instant::now();
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let latency = start.elapsed().as_secs_f64() * 1000.0;
            if xss_unescaped(&body) {
                out.push(
                    ValidatedAnomaly::new(
                        target,
                        url.clone(),
                        format!("Reflected XSS: canary {XSS_REFLECTION_TOKEN} echoed unescaped in parameter `{param}`"),
                        format!(
                            "GET {url} → HTTP {status} ({:.0}ms). Response excerpt contains the live XSS canary unescaped.",
                            latency
                        ),
                    )
                    .with_http_proof("GET", status, excerpt(&body), latency)
                    .with_kind("reflected_xss"),
                );
                return out; // one high-confidence proof is enough for this stage
            }
        }
    }
    out
}

pub async fn probe_csrf(
    target: &str,
    surface: Option<&SurfaceSnap>,
    ctl: &FuzzCampaignCtl,
) -> Vec<ValidatedAnomaly> {
    ctl.add_stage("csrf");
    ctl.add_coverage("form_csrf_token");
    ctl.add_coverage("cookie_samesite");
    let snap = match surface {
        Some(s) => s.clone(),
        None => match probe_surface(target, ctl).await {
            Some(s) => s,
            None => return Vec::new(),
        },
    };
    let mut out = Vec::new();
    if looks_like_form(&snap.body) && !form_has_csrf_token(&snap.body) {
        out.push(
            ValidatedAnomaly::new(
                target,
                target,
                "CSRF: HTML form without anti-CSRF token",
                format!(
                    "GET {target} → HTTP {} ({:.0}ms). Page contains <form> but no csrf/_token/authenticity_token hidden field.",
                    snap.status, snap.latency_ms
                ),
            )
            .with_http_proof("GET", snap.status, excerpt(&snap.body), snap.latency_ms)
            .with_kind("csrf"),
        );
    }
    for c in &snap.cookies {
        if cookie_samesite_weak(c) {
            out.push(
                ValidatedAnomaly::new(
                    target,
                    target,
                    "CSRF: session cookie missing SameSite=Lax/Strict",
                    format!(
                        "GET {target} → HTTP {}. Set-Cookie lacks SameSite=Lax/Strict: {}",
                        snap.status,
                        excerpt(c)
                    ),
                )
                .with_http_proof("GET", snap.status, excerpt(c), snap.latency_ms)
                .with_kind("csrf"),
            );
            break;
        }
    }
    out
}

pub async fn probe_open_redirect(target: &str, ctl: &FuzzCampaignCtl) -> Vec<ValidatedAnomaly> {
    ctl.add_stage("open_redirect");
    ctl.add_coverage("redirect_params");
    let Ok(client) = probe_client(false) else {
        return Vec::new();
    };
    let origin = host_of(target);
    let payloads = [
        format!("https://{REDIRECT_CANARY_HOST}/r"),
        format!("//{REDIRECT_CANARY_HOST}/r"),
        format!("/\\{REDIRECT_CANARY_HOST}/r"),
    ];
    let mut out = Vec::new();
    for param in REDIRECT_PARAMS {
        if ctl.expired() {
            break;
        }
        for payload in &payloads {
            if ctl.expired() {
                break;
            }
            let url = append_query_param(target, param, payload);
            ctl.note_probe(&url);
            let start = Instant::now();
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let refresh = resp
                .headers()
                .get("refresh")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let latency = start.elapsed().as_secs_f64() * 1000.0;
            let body = resp.text().await.unwrap_or_default();
            let loc_hit = location_points_at_canary(&location);
            let refresh_hit = location_points_at_canary(&refresh);
            let meta_hit = body.to_ascii_lowercase().contains(REDIRECT_CANARY_HOST)
                && (body.to_ascii_lowercase().contains("http-equiv=\"refresh\"")
                    || body.to_ascii_lowercase().contains("http-equiv='refresh'"));
            if (loc_hit || refresh_hit || meta_hit)
                && !location.to_ascii_lowercase().contains(&origin)
            {
                let loc_disp = if !location.is_empty() {
                    location.clone()
                } else if !refresh.is_empty() {
                    refresh.clone()
                } else {
                    excerpt(&body)
                };
                out.push(
                    ValidatedAnomaly::new(
                        target,
                        url.clone(),
                        format!("Open redirect via `{param}`"),
                        format!(
                            "GET {url} → HTTP {status} ({:.0}ms). Location/Refresh/meta points at canary host {REDIRECT_CANARY_HOST}: {loc_disp}",
                            latency
                        ),
                    )
                    .with_http_proof("GET", status, loc_disp.clone(), latency)
                    .with_location(loc_disp)
                    .with_kind("open_redirect"),
                );
                return out;
            }
        }
    }
    out
}

pub async fn probe_race(target: &str, ctl: &FuzzCampaignCtl) -> Vec<ValidatedAnomaly> {
    ctl.add_stage("race");
    ctl.add_coverage("concurrent_post");
    let Ok(client) = probe_client(true) else {
        return Vec::new();
    };
    let n = 8usize;
    let body = format!(
        "weissman_race={}&nonce={}",
        XSS_REFLECTION_TOKEN,
        uuid::Uuid::new_v4()
    );
    let mut futs = Vec::new();
    for _ in 0..n {
        if ctl.expired() {
            break;
        }
        ctl.note_probe(target);
        let client = client.clone();
        let url = target.to_string();
        let body = body.clone();
        futs.push(async move {
            let start = Instant::now();
            match client
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    Some((status, text, start.elapsed().as_secs_f64() * 1000.0))
                }
                Err(_) => None,
            }
        });
    }
    let results: Vec<(u16, String, f64)> = futures::future::join_all(futs)
        .await
        .into_iter()
        .flatten()
        .collect();
    if results.len() < 4 {
        return Vec::new();
    }
    let statuses: HashSet<u16> = results.iter().map(|r| r.0).collect();
    let success: Vec<u16> = statuses
        .iter()
        .copied()
        .filter(|s| (200..300).contains(s))
        .collect();
    let has_conflict = statuses.contains(&409) || statuses.contains(&423);
    let mixed_success = success.len() >= 2;
    if !(mixed_success || (success.iter().any(|s| *s == 200) && has_conflict)) {
        return Vec::new();
    }
    let proof = results
        .iter()
        .map(|(s, b, lat)| {
            format!(
                "{s}/{:.0}ms:{}",
                lat,
                excerpt(b).chars().take(80).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let first = &results[0];
    vec![ValidatedAnomaly::new(
        target,
        body,
        "Race condition: concurrent identical POSTs returned divergent success statuses",
        format!(
            "Fired {} concurrent POSTs to {target}. Status set {:?}. Proof: {proof}",
            results.len(),
            statuses
        ),
    )
    .with_http_proof("POST", first.0, excerpt(&first.1), first.2)
    .with_kind("race")]
}

/// Which specialized stages to run for an engine id.
#[must_use]
pub fn stages_for(engine_id: &str) -> &'static [&'static str] {
    match engine_id {
        "xss_advanced" => &["xss"],
        "csrf_exploit" => &["csrf"],
        "race_condition_web" => &["race"],
        "open_redirect" => &["open_redirect"],
        _ => &["xss", "csrf", "open_redirect", "race"],
    }
}

pub async fn run_specialized(
    engine_id: &str,
    target: &str,
    ctl: &FuzzCampaignCtl,
) -> Vec<ValidatedAnomaly> {
    let mut out = Vec::new();
    if ctl.expired() {
        return out;
    }
    let surface = probe_surface(target, ctl).await;
    ctl.emit_progress("surface", out.len()).await;
    for stage in stages_for(engine_id) {
        if ctl.expired() {
            break;
        }
        match *stage {
            "xss" => out.extend(probe_xss(target, ctl).await),
            "csrf" => out.extend(probe_csrf(target, surface.as_ref(), ctl).await),
            "open_redirect" => out.extend(probe_open_redirect(target, ctl).await),
            "race" => out.extend(probe_race(target, ctl).await),
            _ => {}
        }
        ctl.emit_progress(stage, out.len()).await;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::response::Response;
    use axum::routing::get;
    use axum::Router;
    async fn spawn_app(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://127.0.0.1:{}", addr.port()), h)
    }

    fn ctl() -> FuzzCampaignCtl {
        FuzzCampaignCtl::new("test", Duration::from_secs(30))
    }

    #[test]
    fn xss_unescaped_requires_live_canary() {
        assert!(xss_unescaped(&format!(
            "<html><svg/onload=alert('{XSS_REFLECTION_TOKEN}')></html>"
        )));
        assert!(!xss_unescaped("<html>safe</html>"));
        assert!(!xss_unescaped(&format!(
            "&lt;svg&gt;{XSS_REFLECTION_TOKEN}"
        )));
    }

    #[test]
    fn csrf_token_and_samesite_heuristics() {
        assert!(looks_like_form("<FORM action=/x>"));
        assert!(form_has_csrf_token(
            r#"<form><input name="csrf_token" value="a"></form>"#
        ));
        assert!(!form_has_csrf_token("<form><input name=email></form>"));
        assert!(cookie_samesite_weak("sessionid=abc; Path=/"));
        assert!(!cookie_samesite_weak("sessionid=abc; SameSite=Lax"));
        assert!(!cookie_samesite_weak("theme=dark; Path=/"));
    }

    #[test]
    fn redirect_canary_match() {
        assert!(location_points_at_canary(&format!(
            "https://{REDIRECT_CANARY_HOST}/r"
        )));
        assert!(!location_points_at_canary("https://example.com/r"));
    }

    #[tokio::test]
    async fn xss_probe_records_http_proof_on_live_echo() {
        let app = Router::new().route(
            "/",
            get(|req: Request<Body>| async move {
                let q = req.uri().query().unwrap_or("");
                let decoded = urlencoding::decode(q).unwrap_or_default();
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(Body::from(format!("<html>{decoded}</html>")))
                    .unwrap()
            }),
        );
        let (base, _h) = spawn_app(app).await;
        let findings = probe_xss(&base, &ctl()).await;
        assert!(!findings.is_empty(), "expected reflected XSS proof");
        let f = &findings[0];
        assert_eq!(f.http_status, Some(200));
        assert_eq!(f.http_method.as_deref(), Some("GET"));
        assert!(f
            .response_excerpt
            .as_deref()
            .unwrap_or("")
            .contains(XSS_REFLECTION_TOKEN));
        assert_eq!(f.evidence_kind.as_deref(), Some("reflected_xss"));
        assert!(f.has_http_proof());
    }

    #[tokio::test]
    async fn csrf_probe_flags_form_without_token() {
        let app = Router::new().route(
            "/",
            get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::SET_COOKIE, "sessionid=abc; Path=/")
                    .body(Body::from(
                        r#"<html><form method="post" action="/xfer"><input name="amount"></form></html>"#,
                    ))
                    .unwrap()
            }),
        );
        let (base, _h) = spawn_app(app).await;
        let findings = probe_csrf(&base, None, &ctl()).await;
        assert!(
            findings
                .iter()
                .any(|f| f.evidence_kind.as_deref() == Some("csrf")),
            "expected CSRF finding, got {:?}",
            findings
        );
        assert!(findings.iter().all(|f| f.http_status == Some(200)));
    }

    #[tokio::test]
    async fn open_redirect_probe_uses_location_header() {
        let app = Router::new().route(
            "/",
            get(|req: Request<Body>| async move {
                let q = req.uri().query().unwrap_or("");
                if let Some((_, v)) = q.split_once("next=") {
                    let loc = urlencoding::decode(v).unwrap_or_default();
                    return Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, loc.as_ref())
                        .body(Body::empty())
                        .unwrap();
                }
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("ok"))
                    .unwrap()
            }),
        );
        let (base, _h) = spawn_app(app).await;
        let findings = probe_open_redirect(&base, &ctl()).await;
        assert!(
            !findings.is_empty(),
            "expected open-redirect HTTP proof, got none"
        );
        let f = &findings[0];
        assert_eq!(f.http_status, Some(302));
        assert!(f
            .location_header
            .as_deref()
            .unwrap_or("")
            .contains(REDIRECT_CANARY_HOST));
        assert_eq!(f.evidence_kind.as_deref(), Some("open_redirect"));
    }

    #[tokio::test]
    async fn race_probe_flags_divergent_success_codes() {
        use axum::response::IntoResponse;
        use std::sync::atomic::{AtomicU16, Ordering};
        use std::sync::Arc;
        let seq = Arc::new(AtomicU16::new(0));
        let seq2 = seq.clone();
        let app = Router::new().route(
            "/",
            axum::routing::post(move || {
                let seq = seq2.clone();
                async move {
                    let n = seq.fetch_add(1, Ordering::SeqCst);
                    if n % 2 == 0 {
                        (StatusCode::OK, "created").into_response()
                    } else {
                        (StatusCode::CREATED, "also-created").into_response()
                    }
                }
            }),
        );
        let (base, _h) = spawn_app(app).await;
        let findings = probe_race(&base, &ctl()).await;
        assert!(
            !findings.is_empty(),
            "expected race divergence proof from mixed 200/201"
        );
        assert_eq!(findings[0].evidence_kind.as_deref(), Some("race"));
        assert!(findings[0].has_http_proof());
    }

    #[tokio::test]
    async fn race_identical_404_is_not_a_finding() {
        use axum::response::IntoResponse;
        let app = Router::new().route(
            "/",
            axum::routing::post(|| async { (StatusCode::NOT_FOUND, "nope").into_response() }),
        );
        let (base, _h) = spawn_app(app).await;
        let findings = probe_race(&base, &ctl()).await;
        assert!(
            findings.is_empty(),
            "identical 404s must not be reported as a race"
        );
    }

    #[test]
    fn stages_match_engine_ids() {
        assert_eq!(stages_for("xss_advanced"), &["xss"]);
        assert_eq!(stages_for("csrf_exploit"), &["csrf"]);
        assert_eq!(stages_for("race_condition_web"), &["race"]);
        assert_eq!(stages_for("open_redirect"), &["open_redirect"]);
        assert!(stages_for("http_feedback_fuzz").contains(&"xss"));
    }
}
