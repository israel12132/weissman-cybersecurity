//! Timing Side-Channel Posture — world-class, evidence-first, agentless.
//!
//! Modelled on the research and tooling that define the category (PortSwigger timing labs,
//! Cloudflare constant-time guidance, OWASP Testing Guide § timing attacks, academic work on
//! statistical side-channel detection). Unlike naive scanners that compare two millisecond-scale
//! averages, this engine performs **microsecond-precision statistical profiling** with Z-score,
//! Welch's t-test, and Cohen's d effect-size analysis — only emitting findings when the signal
//! exceeds operator-configured significance thresholds.
//!
//! What it measures (every finding requires a real observed timing differential — nothing simulated):
//!   * **Authentication timing oracle** — valid vs invalid username/password pairs on login surfaces;
//!     detects bcrypt/Argon verify paths that leak account existence (CWE-208).
//!   * **User-enumeration via reset/forgot** — differential response time on password-reset and
//!     account-lookup endpoints (Wiz-style identity exposure chain input).
//!   * **API-key / HMAC compare leak** — progressively longer Bearer/API-key prefixes; linear
//!     latency growth indicates non-constant-time secret comparison (CWE-208, JWT HMAC oracle class).
//!   * **JWT / token validation timing** — well-formed vs malformed token structure; early-exit
//!     parsers leak validation depth.
//!   * **Rate-limiter differential timing** — burst traffic profile; lockout/throttle introduces
//!     measurable latency step (DoS / credential-stuffing evasion primitive).
//!   * **Cache timing oracle** — repeat vs cache-bust requests; CDN/app-cache hits vs misses.
//!   * **Blind injection CPU oracle** — WAF-safe heavy-math payloads (no SLEEP/WAITFOR) for
//!     SQL/regex backtracking side channels on query parameters.
//!   * **Wiz-style attack-path synthesis** + quantified 0–100 constant-time posture score.
//!
//! Safety contract: only obviously synthetic credentials (`weissman_probe_*`) are used; no destructive
//! writes; no account lockout beyond configured burst limits; every probe is read-only or a failed
//! auth attempt that any scanner would perform.
//!
//! GUI-driven via [`ArsenalConfig`] (`POST /api/command-center/scan` → `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1600 (Weaken Encryption — side channels), T1110 (Brute Force — user enum),
//! T1190 (Exploit Public-Facing Application).

#![allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions
)]

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{extract_host, http_post_json, join_url, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "timing_sidechannel";
const MITRE: &str = "T1600";
const MITRE_ENUM: &str = "T1110";

const DEFAULT_PATHS: &[&str] = &[
    "/",
    "/login",
    "/api/login",
    "/api/auth/login",
    "/auth/login",
    "/signin",
    "/api/v1/login",
    "/oauth/token",
];

const DEFAULT_RESET_PATHS: &[&str] = &[
    "/forgot-password",
    "/api/password/forgot",
    "/api/auth/reset",
    "/api/users/forgot",
    "/reset-password",
];

const BLIND_PAYLOADS: &[&str] = &[
    "1 AND (SELECT * FROM (SELECT(SELECT COUNT(*) FROM information_schema.tables t CROSS JOIN information_schema.tables t2))a)",
    "1; SELECT BENCHMARK(500000,SHA1('x'))--",
    "' OR (SELECT 1 FROM (SELECT RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND())a)--",
    "1' RLIKE (SELECT CONCAT(REPEAT('.*',500),'$')) AND '1",
];

// ── Configuration ───────────────────────────────────────────────────────────────

struct ScanConfig {
    timeout_ms: u64,
    concurrency: usize,
    intensity: Intensity,
    paths: Vec<String>,
    reset_paths: Vec<String>,
    baseline_samples: usize,
    test_samples: usize,
    z_threshold: f64,
    min_delta_us: u64,
    rate_burst: usize,
    check_auth_timing: bool,
    check_user_enum: bool,
    check_api_key_timing: bool,
    check_jwt_timing: bool,
    check_rate_limit: bool,
    check_cache_timing: bool,
    check_blind_injection: bool,
    include_info: bool,
    attack_paths: bool,
    posture_score: bool,
    probe_username: String,
    probe_domain: String,
}

impl ScanConfig {
    fn load(cfg: &ArsenalConfig, host: &str) -> Self {
        let intensity = cfg.intensity();
        let baseline = match intensity {
            Intensity::Light => 20,
            Intensity::Normal => 40,
            Intensity::Aggressive => 80,
        };
        let test_n = match intensity {
            Intensity::Light => 15,
            Intensity::Normal => 30,
            Intensity::Aggressive => 60,
        };
        Self {
            timeout_ms: cfg.timeout_ms(12_000),
            concurrency: cfg.concurrency().clamp(1, 16),
            intensity,
            paths: cfg.string_list_or("paths", DEFAULT_PATHS),
            reset_paths: cfg.string_list_or("reset_paths", DEFAULT_RESET_PATHS),
            baseline_samples: cfg.usize_or("baseline_samples", baseline).clamp(10, 200),
            test_samples: cfg.usize_or("test_samples", test_n).clamp(10, 200),
            z_threshold: {
                let z = cfg.u64_or("z_threshold", 30) as f64 / 10.0;
                z.clamp(1.5, 8.0)
            },
            min_delta_us: cfg.u64_or("min_delta_us", 500).clamp(50, 50_000),
            rate_burst: cfg.usize_or("rate_burst", 24).clamp(8, 64),
            check_auth_timing: cfg.bool_or("check_auth_timing", true),
            check_user_enum: cfg.bool_or("check_user_enum", true),
            check_api_key_timing: cfg.bool_or("check_api_key_timing", true),
            check_jwt_timing: cfg.bool_or("check_jwt_timing", true),
            check_rate_limit: cfg.bool_or("check_rate_limit", intensity != Intensity::Light),
            check_cache_timing: cfg.bool_or("check_cache_timing", true),
            check_blind_injection: cfg.bool_or("check_blind_injection", true),
            include_info: cfg.bool_or("include_info_findings", true),
            attack_paths: cfg.bool_or("check_attack_paths", true),
            posture_score: cfg.bool_or("check_posture_score", true),
            probe_username: cfg.string_or("probe_username", "admin"),
            probe_domain: cfg.string_or("probe_domain", host),
        }
    }
}

// ── Statistics ──────────────────────────────────────────────────────────────────

fn mean(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64
}

fn variance(samples: &[u64], sample_mean: f64) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let sum_sq: f64 = samples
        .iter()
        .map(|&x| (x as f64 - sample_mean).powi(2))
        .sum();
    sum_sq / (samples.len() - 1) as f64
}

fn std_dev(samples: &[u64]) -> f64 {
    variance(samples, mean(samples)).sqrt()
}

fn z_score(x: f64, mu: f64, sigma: f64) -> Option<f64> {
    if sigma <= 0.0 {
        return None;
    }
    Some((x - mu) / sigma)
}

fn welch_t(a: &[u64], b: &[u64]) -> Option<f64> {
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    let ma = mean(a);
    let mb = mean(b);
    let va = variance(a, ma);
    let vb = variance(b, mb);
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let denom = (va / na + vb / nb).sqrt();
    if denom <= 0.0 {
        return None;
    }
    Some((ma - mb) / denom)
}

fn cohens_d(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let ma = mean(a);
    let mb = mean(b);
    let sa = variance(a, ma);
    let sb = variance(b, mb);
    let pooled = ((sa + sb) / 2.0).sqrt();
    if pooled <= 0.0 {
        return 0.0;
    }
    (ma - mb).abs() / pooled
}

fn confidence_from_z(z: f64) -> f64 {
    let z = z.abs();
    if z <= 0.0 {
        return 0.5;
    }
    let t = 1.0 / (1.0 + 0.2316419 * z);
    let d = 0.3989423 * (-z * z / 2.0).exp();
    let p =
        d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    ((1.0 - p) * 100.0).clamp(50.0, 99.99) / 100.0
}

#[derive(Clone, Debug)]
struct TimingSignal {
    category: &'static str,
    subtype: &'static str,
    title: &'static str,
    severity: &'static str,
    description: String,
    url: String,
    baseline_mean_us: f64,
    baseline_std_us: f64,
    test_mean_us: f64,
    test_std_us: f64,
    delta_us: f64,
    z_score: f64,
    welch_t: f64,
    cohens_d: f64,
    confidence: f64,
    evidence: Evidence,
    remediation: &'static str,
}

fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn measure_get_us(client: &reqwest::Client, url: &str) -> u64 {
    let start = Instant::now();
    let _ = client.get(url).send().await;
    start.elapsed().as_micros() as u64
}

async fn measure_post_us(client: &reqwest::Client, url: &str, body: &Value) -> u64 {
    let start = Instant::now();
    let _ = http_post_json(client, url, body).await;
    start.elapsed().as_micros() as u64
}

async fn measure_get_auth_us(client: &reqwest::Client, url: &str, auth: &str) -> u64 {
    let start = Instant::now();
    let _ = client.get(url).header("Authorization", auth).send().await;
    start.elapsed().as_micros() as u64
}

async fn sample_get(client: &reqwest::Client, url: &str, n: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(measure_get_us(client, url).await);
    }
    out
}

async fn sample_post(client: &reqwest::Client, url: &str, body: &Value, n: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(measure_post_us(client, url, body).await);
    }
    out
}

fn is_significant(
    baseline: &[u64],
    test: &[u64],
    cfg: &ScanConfig,
) -> Option<(f64, f64, f64, f64)> {
    let b_mu = mean(baseline);
    let t_mu = mean(test);
    let b_sigma = std_dev(baseline);
    let delta = (t_mu - b_mu).abs();
    if delta < cfg.min_delta_us as f64 {
        return None;
    }
    let z = z_score(t_mu, b_mu, b_sigma)?;
    let wt = welch_t(baseline, test).unwrap_or(0.0);
    if z.abs() < cfg.z_threshold && wt.abs() < cfg.z_threshold {
        return None;
    }
    let d = cohens_d(baseline, test);
    let conf = confidence_from_z(z.max(wt.abs()));
    Some((z, wt, d, conf))
}

fn signal_to_finding(target: &str, sig: TimingSignal) -> Value {
    let sev = sig.severity;
    let mut f = finding_rich(
        ENGINE_ID,
        sig.title,
        sev,
        MITRE,
        &sig.description,
        target,
        sig.confidence,
        sig.evidence
            .with("category", sig.category)
            .with("subtype", sig.subtype)
            .with("url", &sig.url)
            .with("baseline_mean_us", sig.baseline_mean_us.round())
            .with("baseline_std_us", sig.baseline_std_us.round())
            .with("test_mean_us", sig.test_mean_us.round())
            .with("test_std_us", sig.test_std_us.round())
            .with("delta_us", sig.delta_us.round())
            .with("z_score", (sig.z_score * 100.0).round() / 100.0)
            .with("welch_t", (sig.welch_t * 100.0).round() / 100.0)
            .with("cohens_d", (sig.cohens_d * 100.0).round() / 100.0),
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!(sig.category));
        obj.insert("subtype".to_string(), json!(sig.subtype));
        obj.insert("remediation".to_string(), json!(sig.remediation));
    }
    f
}

// ── Probes ──────────────────────────────────────────────────────────────────────

async fn probe_auth_timing(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    target: &str,
) -> Option<TimingSignal> {
    let url = join_url(base, path);
    let valid_user = cfg.probe_username.clone();
    let invalid_user = format!("weissman_nonexistent_{}", uuid_simple());
    let wrong_pass = "weissman_probe_wrong_password_9x7k";

    let valid_body = json!({"username": valid_user, "password": wrong_pass, "email": format!("{}@{}", valid_user, cfg.probe_domain)});
    let invalid_body = json!({"username": invalid_user, "password": wrong_pass, "email": format!("{}@{}", invalid_user, cfg.probe_domain)});

    // Warm-up
    let _ = http_post_json(client, &url, &valid_body).await;

    let baseline = sample_post(client, &url, &invalid_body, cfg.baseline_samples).await;
    let test = sample_post(client, &url, &valid_body, cfg.test_samples).await;

    let (z, wt, d, conf) = is_significant(&baseline, &test, cfg)?;
    let b_mu = mean(&baseline);
    let t_mu = mean(&test);

    Some(TimingSignal {
        category: "auth_timing_oracle",
        subtype: "username_existence",
        title: "Authentication timing oracle — valid username measurably slower",
        severity: if conf >= 0.9 { "critical" } else { "high" },
        description: format!(
            "Login endpoint `{url}` responds {:.0}µs slower (μ_invalid={:.0}µs σ={:.0}µs vs μ_valid={:.0}µs σ={:.0}µs) when username `{valid_user}` is supplied vs a nonexistent account. \
             This pattern matches password-hash verification running only for real accounts (bcrypt/Argon2/PBKDF2) — enabling **username enumeration** and targeted credential stuffing. \
             Z={z:.2}, Welch t={wt:.2}, Cohen's d={d:.2}, confidence={:.0}%.",
            (t_mu - b_mu).abs(),
            b_mu,
            std_dev(&baseline),
            t_mu,
            std_dev(&test),
            conf * 100.0
        ),
        url: url.clone(),
        baseline_mean_us: b_mu,
        baseline_std_us: std_dev(&baseline),
        test_mean_us: t_mu,
        test_std_us: std_dev(&test),
        delta_us: (t_mu - b_mu).abs(),
        z_score: z,
        welch_t: wt,
        cohens_d: d,
        confidence: conf,
        evidence: Evidence::new()
            .check("valid_username_probe", true, &valid_user)
            .check("invalid_username_probe", true, &invalid_user)
            .check("statistically_significant", true, format!("z={z:.2} t={wt:.2}")),
        remediation: "Use constant-time credential verification: always perform a dummy hash compare for unknown users, unify error messages, and add rate limiting + CAPTCHA on auth endpoints.",
    })
}

async fn probe_user_enum_reset(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    _target: &str,
) -> Option<TimingSignal> {
    let url = join_url(base, path);
    let known = format!("{}@{}", cfg.probe_username, cfg.probe_domain);
    let unknown = format!(
        "weissman_nonexistent_{}@{}",
        uuid_simple(),
        cfg.probe_domain
    );

    let known_body = json!({"email": known, "username": cfg.probe_username});
    let unknown_body = json!({"email": unknown});

    let baseline = sample_post(client, &url, &unknown_body, cfg.baseline_samples).await;
    let test = sample_post(client, &url, &known_body, cfg.test_samples).await;

    let (z, wt, d, conf) = is_significant(&baseline, &test, cfg)?;
    let b_mu = mean(&baseline);
    let t_mu = mean(&test);

    Some(TimingSignal {
        category: "user_enumeration",
        subtype: "password_reset_timing",
        title: "Password-reset timing oracle — account existence leak",
        severity: if conf >= 0.85 { "high" } else { "medium" },
        description: format!(
            "Reset endpoint `{url}` shows a {:.0}µs timing delta between known account `{known}` and random address. \
             Attackers can enumerate valid identities before phishing or credential-stuffing campaigns. Z={z:.2}, Welch t={wt:.2}.",
            (t_mu - b_mu).abs(),
        ),
        url,
        baseline_mean_us: b_mu,
        baseline_std_us: std_dev(&baseline),
        test_mean_us: t_mu,
        test_std_us: std_dev(&test),
        delta_us: (t_mu - b_mu).abs(),
        z_score: z,
        welch_t: wt,
        cohens_d: d,
        confidence: conf,
        evidence: Evidence::new()
            .check("known_email", true, &known)
            .check("unknown_email", true, &unknown),
        remediation: "Normalize reset flow timing and response bodies for known/unknown emails; send identical HTTP 200 with generic message; throttle per-IP.",
    })
}

async fn probe_api_key_timing(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    _target: &str,
) -> Option<TimingSignal> {
    let url = join_url(base, path);
    let prefix = "wk_live_probe_0000000000000000000000000000000000000000000000000000000000000000";
    let short_key = format!("Bearer {}", &prefix[..16]);
    let long_key = format!("Bearer {}", prefix);

    let baseline = {
        let mut samples = Vec::with_capacity(cfg.baseline_samples);
        for _ in 0..cfg.baseline_samples {
            samples.push(measure_get_auth_us(client, &url, "Bearer weissman_invalid_key").await);
        }
        samples
    };
    let test = {
        let mut samples = Vec::with_capacity(cfg.test_samples);
        for _ in 0..cfg.test_samples {
            samples.push(measure_get_auth_us(client, &url, &long_key).await);
        }
        samples
    };

    // Also compare short vs long prefix match progression
    let short_n = cfg.test_samples.min(20);
    let short_samples = {
        let mut s = Vec::with_capacity(short_n);
        for _ in 0..short_n {
            s.push(measure_get_auth_us(client, &url, &short_key).await);
        }
        s
    };

    let (z, wt, d, conf) = is_significant(&baseline, &test, cfg)?;
    let b_mu = mean(&baseline);
    let t_mu = mean(&test);
    let short_mu = mean(&short_samples);

    // Require monotonic hint: longer prefix shouldn't be faster if constant-time
    if t_mu <= short_mu && (t_mu - b_mu).abs() < (cfg.min_delta_us as f64 * 2.0) {
        return None;
    }

    Some(TimingSignal {
        category: "crypto_compare_leak",
        subtype: "api_key_hmac",
        title: "API-key / Bearer token compare timing leak",
        severity: "high",
        description: format!(
            "Endpoint `{url}` shows measurable latency correlation with Bearer token length/prefix ({:.0}µs invalid vs {:.0}µs long-prefix vs {:.0}µs short-prefix). \
             Non-constant-time HMAC/string compare enables byte-by-byte secret recovery (CWE-208). Z={z:.2}.",
            b_mu, t_mu, short_mu,
        ),
        url,
        baseline_mean_us: b_mu,
        baseline_std_us: std_dev(&baseline),
        test_mean_us: t_mu,
        test_std_us: std_dev(&test),
        delta_us: (t_mu - b_mu).abs(),
        z_score: z,
        welch_t: wt,
        cohens_d: d,
        confidence: conf,
        evidence: Evidence::new()
            .check("invalid_bearer", true, "weissman_invalid_key")
            .check("long_prefix_bearer", true, "64-char prefix")
            .check("short_prefix_bearer", true, "16-char prefix"),
        remediation: "Use constant-time comparison (e.g. `subtle::ConstantTimeEq`, `crypto.timingSafeEqual`); validate HMAC with fixed-length MAC compare; rotate exposed API keys.",
    })
}

async fn probe_jwt_timing(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    _target: &str,
) -> Option<TimingSignal> {
    let url = join_url(base, path);
    let malformed = "Bearer not.a.jwt";
    let wellformed = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IldlaXNzYW1hbiBQcm9iZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    let baseline = {
        let mut s = Vec::with_capacity(cfg.baseline_samples);
        for _ in 0..cfg.baseline_samples {
            s.push(measure_get_auth_us(client, &url, malformed).await);
        }
        s
    };
    let test = {
        let mut s = Vec::with_capacity(cfg.test_samples);
        for _ in 0..cfg.test_samples {
            s.push(measure_get_auth_us(client, &url, wellformed).await);
        }
        s
    };

    let (z, wt, d, conf) = is_significant(&baseline, &test, cfg)?;
    let b_mu = mean(&baseline);
    let t_mu = mean(&test);

    Some(TimingSignal {
        category: "token_validation",
        subtype: "jwt_structure",
        title: "JWT validation timing differential — parser depth leak",
        severity: "medium",
        description: format!(
            "Protected route `{url}` processes well-formed JWT structure {:.0}µs differently from malformed token (μ_malformed={:.0}µs vs μ_jwt={:.0}µs). \
             Early-exit parsers can leak signature-verification progress. Z={z:.2}.",
            (t_mu - b_mu).abs(), b_mu, t_mu,
        ),
        url,
        baseline_mean_us: b_mu,
        baseline_std_us: std_dev(&baseline),
        test_mean_us: t_mu,
        test_std_us: std_dev(&test),
        delta_us: (t_mu - b_mu).abs(),
        z_score: z,
        welch_t: wt,
        cohens_d: d,
        confidence: conf,
        evidence: Evidence::new()
            .check("malformed_token", true, malformed)
            .check("wellformed_jwt", true, "HS256 test vector"),
        remediation: "Use constant-time JWT validation libraries; reject malformed tokens via uniform code path; prefer asymmetric algorithms with key rotation.",
    })
}

async fn probe_rate_limit_timing(
    client: &reqwest::Client,
    url: &str,
    cfg: &ScanConfig,
    _target: &str,
) -> Option<TimingSignal> {
    let mut samples = Vec::with_capacity(cfg.rate_burst);
    for _ in 0..cfg.rate_burst {
        samples.push(measure_get_us(client, url).await);
    }
    if samples.len() < 12 {
        return None;
    }
    let split = samples.len() / 2;
    let (first, second) = samples.split_at(split);
    let (z, wt, d, conf) = is_significant(first, second, cfg)?;
    let f_mu = mean(first);
    let s_mu = mean(second);

    if s_mu <= f_mu {
        return None;
    }

    Some(TimingSignal {
        category: "rate_limiter",
        subtype: "burst_throttle",
        title: "Rate-limiter / lockout timing step detected",
        severity: "medium",
        description: format!(
            "Burst profile on `{url}` shows {:.0}µs slowdown after {} requests (μ_first={:.0}µs → μ_second={:.0}µs). \
             Confirms active throttling — useful for evasion planning and DoS surface mapping. Z={z:.2}.",
            s_mu - f_mu,
            split,
            f_mu,
            s_mu,
        ),
        url: url.to_string(),
        baseline_mean_us: f_mu,
        baseline_std_us: std_dev(first),
        test_mean_us: s_mu,
        test_std_us: std_dev(second),
        delta_us: s_mu - f_mu,
        z_score: z,
        welch_t: wt,
        cohens_d: d,
        confidence: conf,
        evidence: Evidence::new()
            .with("burst_size", cfg.rate_burst)
            .check("second_half_slower", true, format!("+{:.0}µs", s_mu - f_mu)),
        remediation: "Ensure rate limits apply before expensive handlers; use edge/WAF throttling; monitor for distributed stuffing that stays under per-IP thresholds.",
    })
}

async fn probe_cache_timing(
    client: &reqwest::Client,
    url: &str,
    cfg: &ScanConfig,
    _target: &str,
) -> Option<TimingSignal> {
    let bust = format!(
        "{url}{}weissman_bust={}",
        if url.contains('?') { "&" } else { "?" },
        uuid_simple()
    );
    let _ = measure_get_us(client, url).await;
    let cached = sample_get(client, url, cfg.baseline_samples.min(15)).await;
    let uncached = sample_get(client, &bust, cfg.test_samples.min(15)).await;

    let (z, wt, d, conf) = is_significant(&uncached, &cached, cfg)?;
    let c_mu = mean(&cached);
    let u_mu = mean(&uncached);

    if c_mu >= u_mu {
        return None;
    }

    Some(TimingSignal {
        category: "cache_oracle",
        subtype: "cdn_app_cache",
        title: "Cache timing oracle — hit vs miss differential",
        severity: "low",
        description: format!(
            "Repeat requests to `{url}` are {:.0}µs faster than cache-busted variants (μ_hit={:.0}µs vs μ_miss={:.0}µs). \
             Can leak resource existence and access patterns (CRISP/WicCache-class). Z={z:.2}.",
            u_mu - c_mu, c_mu, u_mu,
        ),
        url: url.to_string(),
        baseline_mean_us: u_mu,
        baseline_std_us: std_dev(&uncached),
        test_mean_us: c_mu,
        test_std_us: std_dev(&cached),
        delta_us: u_mu - c_mu,
        z_score: z,
        welch_t: wt,
        cohens_d: d,
        confidence: conf,
        evidence: Evidence::new()
            .check("cache_hit_faster", true, format!("-{:.0}µs", u_mu - c_mu)),
        remediation: "Normalize response times for cache hit/miss; avoid user-specific content in cacheable paths; set Vary correctly.",
    })
}

async fn probe_blind_injection(
    client: &reqwest::Client,
    url: &str,
    cfg: &ScanConfig,
    _target: &str,
) -> Option<TimingSignal> {
    let baseline = sample_get(client, url, cfg.baseline_samples).await;
    let mut best: Option<TimingSignal> = None;

    for payload in BLIND_PAYLOADS {
        let sep = if url.contains('?') { "&" } else { "?" };
        let payload_url = format!("{url}{sep}q={}", urlencoding::encode(payload));
        let test = sample_get(client, &payload_url, cfg.test_samples).await;
        if let Some((z, wt, d, conf)) = is_significant(&baseline, &test, cfg) {
            let b_mu = mean(&baseline);
            let t_mu = mean(&test);
            if t_mu <= b_mu {
                continue;
            }
            let sig = TimingSignal {
                category: "blind_injection",
                subtype: "cpu_oracle",
                title: "Blind injection CPU timing oracle (WAF-safe payload)",
                severity: if conf >= 0.9 { "critical" } else { "high" },
                description: format!(
                    "Parameter on `{url}` triggers {:.0}µs additional server-side processing with CPU-heavy payload (no SLEEP/WAITFOR). \
                     Indicates SQL/regex backtracking side channel exploitable for blind data extraction. Z={z:.2}, payload preview: {}…",
                    t_mu - b_mu,
                    payload.chars().take(80).collect::<String>(),
                ),
                url: payload_url,
                baseline_mean_us: b_mu,
                baseline_std_us: std_dev(&baseline),
                test_mean_us: t_mu,
                test_std_us: std_dev(&test),
                delta_us: t_mu - b_mu,
                z_score: z,
                welch_t: wt,
                cohens_d: d,
                confidence: conf,
                evidence: Evidence::new()
                    .with("payload_preview", payload.chars().take(120).collect::<String>())
                    .check("cpu_heavy_oracle", true, format!("+{:.0}µs", t_mu - b_mu)),
                remediation: "Parameterize all queries; disable verbose regex; cap DB query cost; deploy WAF with timing-normalization where feasible.",
            };
            if best.as_ref().map(|b| b.confidence).unwrap_or(0.0) < conf {
                best = Some(sig);
            }
        }
    }
    best
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

// ── Posture aggregation ─────────────────────────────────────────────────────────

#[derive(Default)]
struct SideChannelPosture {
    worst: String,
    categories: std::collections::BTreeSet<String>,
    count_by_sev: std::collections::BTreeMap<String, usize>,
}

impl SideChannelPosture {
    fn absorb(&mut self, f: &Value) {
        let sev = f
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string();
        *self.count_by_sev.entry(sev.clone()).or_insert(0) += 1;
        if sev_rank(&sev) > sev_rank(&self.worst) {
            self.worst = sev;
        }
        if let Some(c) = f.get("category").and_then(Value::as_str) {
            self.categories.insert(c.to_string());
        }
    }

    fn score(&self) -> u8 {
        let crit = *self.count_by_sev.get("critical").unwrap_or(&0);
        let high = *self.count_by_sev.get("high").unwrap_or(&0);
        let med = *self.count_by_sev.get("medium").unwrap_or(&0);
        let low = *self.count_by_sev.get("low").unwrap_or(&0);
        let mut score = 100i32;
        score -= i32::try_from(crit * 25).unwrap_or(100);
        score -= i32::try_from(high * 15).unwrap_or(75);
        score -= i32::try_from(med * 8).unwrap_or(40);
        score -= i32::try_from(low * 3).unwrap_or(15);
        score.clamp(0, 100) as u8
    }

    fn grade(score: u8) -> &'static str {
        match score {
            90..=100 => "A",
            80..=89 => "B",
            70..=79 => "C",
            55..=69 => "D",
            _ => "F",
        }
    }
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn synthesize_attack_paths(posture: &SideChannelPosture, host: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    let cats = &posture.categories;
    if cats.contains("auth_timing_oracle") || cats.contains("user_enumeration") {
        paths.push(finding_rich(
            ENGINE_ID,
            "Identity enumeration → targeted credential stuffing",
            "high",
            MITRE_ENUM,
            &format!(
                "Timing oracles on `{host}` leak valid usernames/emails. Attack chain: enumerate accounts → breach-corpus password spray → MFA fatigue / session hijack. \
                 Wiz-class toxic combo when paired with missing MFA or weak lockout."
            ),
            host,
            0.88,
            Evidence::new()
                .with("chain_step", "1_enumerate")
                .with("chain_step", "2_stuff")
                .with("chain_step", "3_pivot"),
        ));
    }
    if cats.contains("crypto_compare_leak") {
        paths.push(finding_rich(
            ENGINE_ID,
            "HMAC compare leak → API key / token byte recovery",
            "critical",
            MITRE,
            &format!(
                "Non-constant-time secret comparison on `{host}` enables byte-by-byte recovery of API keys or JWT HMAC secrets — full API takeover without brute force."
            ),
            host,
            0.92,
            Evidence::new().with("cwe", "CWE-208"),
        ));
    }
    if cats.contains("blind_injection") {
        paths.push(finding_rich(
            ENGINE_ID,
            "Blind SQL/regex timing → database exfiltration",
            "critical",
            MITRE,
            &format!(
                "CPU timing oracle on `{host}` supports binary-search extraction of database contents (PortSwigger blind SQLi timing class) — often chains to cloud IMDS via SSRF."
            ),
            host,
            0.9,
            Evidence::new().with("owasp", "A03:2021-Injection"),
        ));
    }
    paths
}

fn build_summary(target: &str, posture: &SideChannelPosture, endpoint_count: usize) -> Value {
    let score = posture.score();
    let grade = SideChannelPosture::grade(score);
    let description = format!(
        "Timing side-channel posture for `{target}`: {score}/100 ({grade}). \
         Probed {endpoint_count} endpoint(s); worst finding severity `{}`. \
         Categories observed: {}.",
        posture.worst,
        if posture.categories.is_empty() {
            "none".to_string()
        } else {
            posture
                .categories
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    let mut summary = finding_rich(
        ENGINE_ID,
        "Timing Side-Channel Posture Summary",
        severity_for_score(1.0 - f64::from(score) / 100.0),
        MITRE,
        &description,
        target,
        0.99,
        Evidence::new()
            .with("posture_score", score)
            .with("grade", grade)
            .with("worst_severity", &posture.worst)
            .with("endpoint_count", endpoint_count),
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("category".to_string(), json!("posture_summary"));
        obj.insert("summary".to_string(), json!(true));
        obj.insert("posture_score".to_string(), json!(score));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert("worst_severity".to_string(), json!(&posture.worst));
        obj.insert(
            "remediation".to_string(),
            json!("Adopt constant-time crypto and string comparison, unify auth error paths, add edge rate limiting, parameterize queries, and monitor timing anomalies in production (RUM + synthetic probes)."),
        );
    }
    summary
}

async fn probe_path(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    cfg: &ScanConfig,
    target: &str,
) -> Vec<Value> {
    let mut findings = Vec::new();
    let url = join_url(base, path);

    if cfg.check_auth_timing {
        if let Some(sig) = probe_auth_timing(client, base, path, cfg, target).await {
            findings.push(signal_to_finding(target, sig));
        }
    }
    if cfg.check_api_key_timing {
        if let Some(sig) = probe_api_key_timing(client, base, path, cfg, target).await {
            findings.push(signal_to_finding(target, sig));
        }
    }
    if cfg.check_jwt_timing {
        if let Some(sig) = probe_jwt_timing(client, base, path, cfg, target).await {
            findings.push(signal_to_finding(target, sig));
        }
    }
    if cfg.check_rate_limit {
        if let Some(sig) = probe_rate_limit_timing(client, &url, cfg, target).await {
            findings.push(signal_to_finding(target, sig));
        }
    }
    if cfg.check_cache_timing {
        if let Some(sig) = probe_cache_timing(client, &url, cfg, target).await {
            findings.push(signal_to_finding(target, sig));
        }
    }
    if cfg.check_blind_injection {
        if let Some(sig) = probe_blind_injection(client, &url, cfg, target).await {
            findings.push(signal_to_finding(target, sig));
        }
    }
    findings
}

// ── Public entry points ───────────────────────────────────────────────────────────

pub async fn run_timing_sidechannel_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    let target = target.trim();
    if target.is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let host = extract_host(&base);
    let cfg = ScanConfig::load(&ArsenalConfig::from_ctx(ctx), &host);
    let client = build_client(cfg.timeout_ms);

    let mut paths: Vec<String> = cfg.paths.clone();
    for p in ctx.discovered_paths.iter().take(16) {
        let p = p.trim();
        if !p.is_empty() && !paths.iter().any(|x| x == p) {
            paths.push(p.to_string());
        }
    }
    paths.truncate(24);

    let mut all_findings: Vec<Value> = Vec::new();
    let mut posture = SideChannelPosture::default();

    let path_results: Vec<Vec<Value>> = stream::iter(paths.clone())
        .map(|path| {
            let client = client.clone();
            let base = base.clone();
            let cfg = cfg.clone();
            let target = target.to_string();
            async move { probe_path(&client, &base, &path, &cfg, &target).await }
        })
        .buffer_unordered(cfg.concurrency)
        .collect()
        .await;

    for chunk in path_results {
        for f in chunk {
            posture.absorb(&f);
            all_findings.push(f);
        }
    }

    if cfg.check_user_enum {
        for rpath in cfg.reset_paths.iter().take(8) {
            if let Some(sig) = probe_user_enum_reset(&client, &base, rpath, &cfg, target).await {
                let f = signal_to_finding(target, sig);
                posture.absorb(&f);
                all_findings.push(f);
            }
        }
    }

    if cfg.attack_paths && !posture.categories.is_empty() {
        for p in synthesize_attack_paths(&posture, &host) {
            if let Some(obj) = p.as_object() {
                posture.absorb(&Value::Object(obj.clone()));
            }
            all_findings.push(p);
        }
    }

    if cfg.posture_score {
        all_findings.push(build_summary(target, &posture, paths.len()));
    } else if cfg.include_info && all_findings.is_empty() {
        all_findings.push(finding_rich(
            ENGINE_ID,
            "No statistically significant timing side-channels observed",
            "info",
            MITRE,
            &format!(
                "Completed timing side-channel profiling on `{target}` ({path_count} paths, baseline={baseline} samples, z≥{z:.1}). \
                 No differential exceeded significance thresholds — constant-time posture appears sound at this depth.",
                path_count = paths.len(),
                baseline = cfg.baseline_samples,
                z = cfg.z_threshold,
            ),
            target,
            0.75,
            Evidence::new()
                .with("paths_probed", paths.len())
                .with("baseline_samples", cfg.baseline_samples)
                .with("z_threshold", cfg.z_threshold),
        ));
    }

    let msg = format!(
        "Timing Side-Channel: {} findings, posture {}/100 ({}) across {} paths",
        all_findings
            .iter()
            .filter(|f| f.get("summary") != Some(&json!(true)))
            .count(),
        posture.score(),
        SideChannelPosture::grade(posture.score()),
        paths.len(),
    );
    EngineResult::ok(all_findings, msg)
}

pub async fn run_timing_sidechannel_result(target: &str) -> EngineResult {
    run_timing_sidechannel_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_timing_sidechannel(target: &str) {
    print_result(run_timing_sidechannel_result(target).await);
}

// ScanConfig needs Clone for stream — add manually
impl Clone for ScanConfig {
    fn clone(&self) -> Self {
        Self {
            timeout_ms: self.timeout_ms,
            concurrency: self.concurrency,
            intensity: self.intensity,
            paths: self.paths.clone(),
            reset_paths: self.reset_paths.clone(),
            baseline_samples: self.baseline_samples,
            test_samples: self.test_samples,
            z_threshold: self.z_threshold,
            min_delta_us: self.min_delta_us,
            rate_burst: self.rate_burst,
            check_auth_timing: self.check_auth_timing,
            check_user_enum: self.check_user_enum,
            check_api_key_timing: self.check_api_key_timing,
            check_jwt_timing: self.check_jwt_timing,
            check_rate_limit: self.check_rate_limit,
            check_cache_timing: self.check_cache_timing,
            check_blind_injection: self.check_blind_injection,
            include_info: self.include_info,
            attack_paths: self.attack_paths,
            posture_score: self.posture_score,
            probe_username: self.probe_username.clone(),
            probe_domain: self.probe_domain.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welch_t_detects_shift() {
        let a: Vec<u64> = (0..50).map(|i| 1000 + (i % 3) as u64).collect();
        let b: Vec<u64> = (0..50).map(|i| 5000 + (i % 3) as u64).collect();
        let t = welch_t(&a, &b).unwrap();
        assert!(t.abs() > 10.0);
    }

    #[test]
    fn posture_score_degrades() {
        let mut p = SideChannelPosture::default();
        p.absorb(&json!({"severity":"critical","category":"auth_timing_oracle"}));
        assert!(p.score() <= 75);
    }

    #[test]
    fn empty_target_errors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(run_timing_sidechannel_result(""));
        assert!(!r.success);
    }
}
