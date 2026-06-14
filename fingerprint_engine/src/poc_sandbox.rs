//! Sandboxed PoC re-execution for TRUE Proof-of-Exploit verification.
//!
//! After the synthesis engine produces a candidate PoC, this module **independently re-runs it**
//! against the (already scope-validated) target inside an isolated executor and captures a
//! tamper-evident transcript. A finding is only upgraded to "sandbox-verified" when a
//! **deterministic** signal is observed:
//!
//!   * an OAST callback correlated to the payload's collaborator token, or
//!   * the expected verification marker reflected in the live response.
//!
//! Executors (selected at runtime, reported honestly in the verdict):
//!   * `docker:<image>` — the request is issued from inside an ephemeral, resource-capped container
//!     (`--rm --memory --cpus --stop-timeout`), isolating any PoC tooling from the host. Used when
//!     `WEISSMAN_POC_SANDBOX_IMAGE` is set and the `docker` CLI is reachable.
//!   * `pinned_host` — a dedicated reqwest client (capped time/redirects/body, proxy disabled).
//!     Always available; used as the portable fallback.
//!
//! Safety: the target is re-validated through [`crate::security_hardening::validate_poe_target_url`]
//! (SSRF / scheme / cloud-metadata guard) before any request leaves the process. There is **no
//! fabricated success** — when neither executor can run, or no deterministic signal is observed,
//! the verdict is `verified = false`.

use sha2::{Digest, Sha256};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Hard ceiling on a single sandbox HTTP execution.
const SANDBOX_TIMEOUT_SECS: u64 = 15;
/// Cap on the captured transcript that feeds the evidence digest / preview.
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
/// Human-facing evidence preview length.
const PREVIEW_CHARS: usize = 512;

/// Confidence (0–100, matching the PoE verification scale) for each deterministic signal.
const CONFIDENCE_OAST: f64 = 99.0;
const CONFIDENCE_MARKER: f64 = 92.0;

/// Structured outcome of one sandbox re-execution. Serialized onto the finding for auditability.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PocVerdict {
    /// Which executor actually ran the PoC (`docker:<image>` or `pinned_host`).
    pub executor: String,
    /// Whether the PoC was actually executed (false when blocked by the scope guard or no executor ran).
    pub executed: bool,
    /// True only on a deterministic signal (OAST callback or expected marker reflected).
    pub verified: bool,
    /// 0–100 confidence consistent with the PoE verification ladder.
    pub confidence: f64,
    /// HTTP status observed during re-execution (0 when no response).
    pub http_status: u16,
    /// Expected marker observed in the live response/headers.
    pub marker_matched: bool,
    /// OAST collaborator callback correlated to the payload token.
    pub oast_correlated: bool,
    /// Discrete signal classification: `oast` | `marker` | `none` | `blocked` | `error`.
    pub signal: String,
    /// SHA-256 over `executor | status | transcript` — tamper-evident evidence anchor.
    pub evidence_sha256: String,
    /// Truncated, control-char-stripped transcript preview.
    pub evidence_preview: String,
    /// Populated when the executor failed or the target was rejected.
    pub error: Option<String>,
}

impl PocVerdict {
    fn blocked(reason: &str) -> Self {
        Self {
            executor: "none".to_string(),
            executed: false,
            verified: false,
            confidence: 0.0,
            http_status: 0,
            marker_matched: false,
            oast_correlated: false,
            signal: "blocked".to_string(),
            evidence_sha256: evidence_digest("none", 0, reason),
            evidence_preview: sanitize_preview(reason),
            error: Some(reason.to_string()),
        }
    }
}

/// Whether sandbox re-verification is enabled. Off by default so it never adds latency unless an
/// operator opts in; the docker isolation path is further gated on `WEISSMAN_POC_SANDBOX_IMAGE`.
pub fn sandbox_enabled() -> bool {
    truthy(&std::env::var("WEISSMAN_POC_SANDBOX").unwrap_or_default())
}

fn truthy(v: &str) -> bool {
    let v = v.trim();
    v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
}

fn docker_image() -> Option<String> {
    let img = std::env::var("WEISSMAN_POC_SANDBOX_IMAGE").unwrap_or_default();
    let img = img.trim().to_string();
    if img.is_empty() {
        None
    } else {
        Some(img)
    }
}

fn docker_network() -> String {
    let n = std::env::var("WEISSMAN_POC_SANDBOX_NETWORK").unwrap_or_default();
    let n = n.trim().to_string();
    if n.is_empty() {
        "bridge".to_string()
    } else {
        n
    }
}

fn ensure_scheme(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

/// Build the concrete HTTP request from the synthesized PoC, mirroring the engine's own dispatch:
/// GET-mode encodes the payload as `?poc=<urlencoded>`, otherwise the payload is the POST body.
fn build_http_request(
    target: &str,
    method: &str,
    poc: &str,
) -> (reqwest::Method, String, Option<String>) {
    let get_mode = poc.starts_with('?') || method.eq_ignore_ascii_case("GET");
    if get_mode {
        let q = format!("?poc={}", urlencoding::encode(poc));
        (reqwest::Method::GET, format!("{target}{q}"), None)
    } else {
        (
            reqwest::Method::POST,
            target.to_string(),
            Some(poc.to_string()),
        )
    }
}

/// Deterministic verdict from observed signals. Pure — unit-tested.
pub fn decide_signal(
    oast_correlated: bool,
    marker_matched: bool,
    status: u16,
) -> (bool, f64, &'static str) {
    if oast_correlated {
        (true, CONFIDENCE_OAST, "oast")
    } else if marker_matched {
        (true, CONFIDENCE_MARKER, "marker")
    } else {
        // No deterministic signal: not verified. A live 2xx is mild corroboration only.
        let corroboration = if (200..300).contains(&status) {
            15.0
        } else {
            0.0
        };
        (false, corroboration, "none")
    }
}

/// SHA-256 over `executor | status | transcript`, hex-encoded. Pure — unit-tested.
pub fn evidence_digest(executor: &str, status: u16, transcript: &str) -> String {
    let mut h = Sha256::new();
    h.update(executor.as_bytes());
    h.update([0u8]);
    h.update(status.to_string().as_bytes());
    h.update([0u8]);
    let bytes = transcript.as_bytes();
    let capped = &bytes[..bytes.len().min(MAX_CAPTURE_BYTES)];
    h.update(capped);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sanitize_preview(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\t' || !c.is_control() {
                c
            } else {
                ' '
            }
        })
        .take(PREVIEW_CHARS)
        .collect()
}

/// Parse the `WEISSMAN_HTTP_STATUS:<code>` sentinel emitted by the sandbox curl invocation and
/// return `(status, transcript_without_sentinel)`. Pure — unit-tested.
pub fn parse_docker_status(captured: &str) -> (u16, String) {
    const MARKER: &str = "WEISSMAN_HTTP_STATUS:";
    let mut status = 0u16;
    let mut kept: Vec<&str> = Vec::new();
    for line in captured.lines() {
        if let Some(rest) = line.trim().strip_prefix(MARKER) {
            if let Ok(code) = rest.trim().parse::<u16>() {
                status = code;
            }
            continue;
        }
        kept.push(line);
    }
    (status, kept.join("\n"))
}

/// Verify a synthesized PoC by reproducing it in an isolated executor and observing a deterministic
/// signal. `oast_client` is reused for collaborator polling so correlation shares the engine's egress.
pub async fn verify_poc(
    target: &str,
    method: &str,
    poc_payload: &str,
    expected_marker: &str,
    oast_token: Option<&str>,
    oast_client: &reqwest::Client,
) -> PocVerdict {
    let scoped = ensure_scheme(target);
    // Defense-in-depth scope/SSRF guard — refuse to fire at metadata/loopback/non-http targets even
    // though upstream scan-scope validation already ran.
    if let Err(e) = crate::security_hardening::validate_poe_target_url(&scoped) {
        return PocVerdict::blocked(e);
    }

    // OAST correlation is independent of the HTTP executor: the callback (if any) already happened
    // when the engine fired the payload; here we confirm it was observed by the collaborator.
    let oast_correlated = match oast_token {
        Some(t) if !t.is_empty() && crate::fuzz_oob::oast_correlation_enabled() => {
            crate::fuzz_oob::verify_oob_token_seen_with_client(oast_client, t).await
        }
        _ => false,
    };

    let (executor, executed, status, transcript, exec_err) =
        run_in_executor(&scoped, method, poc_payload).await;

    let marker_matched = !expected_marker.is_empty() && transcript.contains(expected_marker);
    let (verified, confidence, mut signal) = decide_signal(oast_correlated, marker_matched, status);
    if !executed && !oast_correlated {
        // Could not reproduce and no out-of-band callback: report honestly as an error, not "none".
        signal = "error";
    }

    PocVerdict {
        evidence_sha256: evidence_digest(&executor, status, &transcript),
        evidence_preview: sanitize_preview(&transcript),
        executor,
        executed,
        verified,
        confidence,
        http_status: status,
        marker_matched,
        oast_correlated,
        signal: signal.to_string(),
        error: exec_err,
    }
}

async fn run_in_executor(
    target: &str,
    method: &str,
    poc: &str,
) -> (String, bool, u16, String, Option<String>) {
    if let Some(image) = docker_image() {
        if docker_available().await {
            return run_in_docker(&image, target, method, poc).await;
        }
    }
    run_pinned_host(target, method, poc).await
}

async fn docker_available() -> bool {
    let fut = Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match tokio::time::timeout(Duration::from_secs(4), fut).await {
        Ok(Ok(s)) => s.success(),
        _ => false,
    }
}

async fn run_in_docker(
    image: &str,
    target: &str,
    method: &str,
    poc: &str,
) -> (String, bool, u16, String, Option<String>) {
    let executor = format!("docker:{image}");
    let (m, url, body) = build_http_request(target, method, poc);
    let method_up = m.as_str().to_string();
    let net = docker_network();

    let mut cmd = Command::new("docker");
    cmd.arg("run")
        .arg("--rm")
        .arg("--pull")
        .arg("never")
        .arg("--network")
        .arg(&net)
        .arg("--memory")
        .arg("256m")
        .arg("--cpus")
        .arg("0.5")
        .arg("--stop-timeout")
        .arg("5")
        .arg("--entrypoint")
        .arg("curl")
        .arg(image)
        .arg("-sS")
        .arg("-k")
        .arg("-i")
        .arg("-m")
        .arg(SANDBOX_TIMEOUT_SECS.to_string())
        .arg("-w")
        .arg("\nWEISSMAN_HTTP_STATUS:%{http_code}\n")
        .arg("-X")
        .arg(&method_up);
    if let Some(b) = &body {
        cmd.arg("-d").arg(b);
    }
    cmd.arg("--").arg(&url);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let fut = cmd.output();
    let out = match tokio::time::timeout(Duration::from_secs(SANDBOX_TIMEOUT_SECS + 10), fut).await
    {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return (
                executor,
                false,
                0,
                String::new(),
                Some(format!("docker spawn: {e}")),
            )
        }
        Err(_) => {
            return (
                executor,
                false,
                0,
                String::new(),
                Some("docker sandbox timed out".to_string()),
            )
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let capped: String = stdout.chars().take(MAX_CAPTURE_BYTES).collect();
    let (status, transcript) = parse_docker_status(&capped);
    if status == 0 && transcript.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return (
            executor,
            out.status.success(),
            0,
            String::new(),
            Some(format!(
                "docker curl produced no response: {}",
                stderr.chars().take(200).collect::<String>()
            )),
        );
    }
    (executor, true, status, transcript, None)
}

async fn run_pinned_host(
    target: &str,
    method: &str,
    poc: &str,
) -> (String, bool, u16, String, Option<String>) {
    let executor = "pinned_host".to_string();
    let (m, url, body) = build_http_request(target, method, poc);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(SANDBOX_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(reqwest::redirect::Policy::limited(3))
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                executor,
                false,
                0,
                String::new(),
                Some(format!("client build: {e}")),
            )
        }
    };

    let mut req = client.request(m, &url);
    if let Some(b) = body {
        req = req.body(b);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return (executor, false, 0, String::new(), Some(e.to_string())),
    };
    let status = resp.status().as_u16();
    let mut transcript = String::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(vs) = v.to_str() {
            transcript.push_str(k.as_str());
            transcript.push_str(": ");
            transcript.push_str(vs);
            transcript.push('\n');
        }
    }
    transcript.push('\n');
    let body_text = resp.text().await.unwrap_or_default();
    transcript.push_str(&body_text);
    let capped: String = transcript.chars().take(MAX_CAPTURE_BYTES).collect();
    (executor, true, status, capped, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthy_variants() {
        assert!(truthy("1"));
        assert!(truthy("true"));
        assert!(truthy("YES"));
        assert!(!truthy("0"));
        assert!(!truthy(""));
        assert!(!truthy("off"));
    }

    #[test]
    fn decide_signal_prefers_oast() {
        let (v, c, s) = decide_signal(true, true, 200);
        assert!(v);
        assert_eq!(s, "oast");
        assert_eq!(c, CONFIDENCE_OAST);
    }

    #[test]
    fn decide_signal_marker_when_no_oast() {
        let (v, c, s) = decide_signal(false, true, 200);
        assert!(v);
        assert_eq!(s, "marker");
        assert_eq!(c, CONFIDENCE_MARKER);
    }

    #[test]
    fn decide_signal_none_is_unverified() {
        let (v, c, s) = decide_signal(false, false, 200);
        assert!(!v);
        assert_eq!(s, "none");
        assert!(c < CONFIDENCE_MARKER);
        let (v2, c2, _) = decide_signal(false, false, 500);
        assert!(!v2);
        assert_eq!(c2, 0.0);
    }

    #[test]
    fn evidence_digest_is_stable_and_sensitive() {
        let a = evidence_digest("pinned_host", 200, "hello");
        let b = evidence_digest("pinned_host", 200, "hello");
        let c = evidence_digest("pinned_host", 200, "hellp");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn build_get_request_encodes_payload() {
        let (m, url, body) = build_http_request("https://e.test/", "GET", "1' OR '1'='1");
        assert_eq!(m, reqwest::Method::GET);
        assert!(url.starts_with("https://e.test/?poc="));
        assert!(url.contains("%27"));
        assert!(body.is_none());
    }

    #[test]
    fn build_post_request_uses_body() {
        let (m, url, body) = build_http_request("https://e.test/api", "POST", "{\"a\":1}");
        assert_eq!(m, reqwest::Method::POST);
        assert_eq!(url, "https://e.test/api");
        assert_eq!(body.as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn parse_docker_status_extracts_marker() {
        let captured = "HTTP/1.1 200 OK\r\nServer: x\n\nbody-line\nWEISSMAN_HTTP_STATUS:200\n";
        let (status, transcript) = parse_docker_status(captured);
        assert_eq!(status, 200);
        assert!(transcript.contains("body-line"));
        assert!(!transcript.contains("WEISSMAN_HTTP_STATUS"));
    }

    #[test]
    fn sanitize_preview_strips_control_and_caps() {
        let raw = format!("ok\u{0007}line{}", "x".repeat(2000));
        let p = sanitize_preview(&raw);
        assert!(!p.contains('\u{0007}'));
        assert!(p.chars().count() <= PREVIEW_CHARS);
    }

    #[tokio::test]
    async fn blocks_metadata_target() {
        let dummy = reqwest::Client::new();
        let v = verify_poc(
            "http://169.254.169.254/latest/meta-data/",
            "GET",
            "x",
            "",
            None,
            &dummy,
        )
        .await;
        assert!(!v.verified);
        assert!(!v.executed);
        assert_eq!(v.signal, "blocked");
    }
}
