//! Inference / blind-oracle defenses for `POST /api/ask`.
//!
//! Two independent gates, both fail-closed for the caller:
//!   1. Hard per-user rate limit — 10 questions / 60 s. When `REDIS_URL` is set,
//!      Redis is mandatory: a timeout, hang, or crash is **503**, never a bypass
//!      onto the in-process governor. Governor is defense-in-depth only after a
//!      successful Redis increment (or when Redis is not configured in non-prod).
//!   2. Semantic / enumeration detector — sequential "starts with A / B / C" and
//!      near-duplicate questions that only flip one letter are treated as automated
//!      table scanning and rejected.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU32;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hard ceiling — never raised, even if the env var is set higher.
pub const ASK_PER_MINUTE_CAP: u32 = 10;
const HISTORY_KEEP: usize = 8;
const HISTORY_TTL: Duration = Duration::from_secs(120);
/// Trigram cosine at or above this + a one-character slot flip ⇒ oracle scan.
const SIMILARITY_ORACLE: f64 = 0.86;

fn ask_per_minute() -> NonZeroU32 {
    let n = std::env::var("WEISSMAN_ASK_PER_MINUTE")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(ASK_PER_MINUTE_CAP)
        .min(ASK_PER_MINUTE_CAP);
    NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
}

fn limiter() -> ArcLimiter {
    static LIM: OnceLock<ArcLimiter> = OnceLock::new();
    LIM.get_or_init(|| {
        let q = Quota::per_minute(ask_per_minute()).allow_burst(ask_per_minute());
        std::sync::Arc::new(RateLimiter::keyed(q))
    })
    .clone()
}

type ArcLimiter = std::sync::Arc<RateLimiter<i64, DefaultKeyedStateStore<i64>, DefaultClock>>;

struct Hist {
    items: VecDeque<(Instant, String)>,
}

fn history() -> &'static Mutex<HashMap<i64, Hist>> {
    static H: OnceLock<Mutex<HashMap<i64, Hist>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Client-safe 503 — Redis configured but unreachable. Does not name Redis.
fn ask_store_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "ok": false,
            "detail": "Ask Weissman is temporarily unavailable.",
        })),
    )
        .into_response()
}

/// Decision after consulting the distributed Ask counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisAdmit {
    Continue,
    RateLimited,
    Unavailable,
}

/// Fail-closed Redis gate for `/api/ask`.
///
/// * `configured` — `REDIS_URL` is set (Redis is the intended store).
/// * `enabled` — the Redis client initialized.
/// * `op` — result of `incr_ask_user_strict` when `enabled`.
/// * `required` — production multi-replica (must not degrade to memory).
#[must_use]
pub fn decide_redis_admit(
    configured: bool,
    enabled: bool,
    op: Option<crate::http::rate_limit_redis::StrictOp<u64>>,
    required: bool,
    limit: u64,
) -> RedisAdmit {
    if configured {
        if !enabled {
            return RedisAdmit::Unavailable;
        }
        return match op.unwrap_or(crate::http::rate_limit_redis::StrictOp::Unavailable) {
            crate::http::rate_limit_redis::StrictOp::Ok(count) if count > limit => {
                RedisAdmit::RateLimited
            }
            crate::http::rate_limit_redis::StrictOp::Ok(_) => RedisAdmit::Continue,
            crate::http::rate_limit_redis::StrictOp::Unavailable => RedisAdmit::Unavailable,
        };
    }
    if required {
        RedisAdmit::Unavailable
    } else {
        RedisAdmit::Continue
    }
}

/// Client-safe 429 — does not confirm whether the trip was rate or oracle detection.
fn ask_limited_response(retry_after_secs: u64) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "ok": false,
            "code": "rate_limited",
            "detail": "Ask Weissman is temporarily unavailable. Retry later.",
            "retry_after_seconds": retry_after_secs,
            "limit_per_minute": ask_per_minute().get(),
        })),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("Retry-After", v);
    }
    resp
}

/// Admit one `/api/ask` question for `user_id`. Records the question on success.
pub async fn admit_ask(user_id: i64, question: &str) -> Result<(), Response> {
    let limit = ask_per_minute().get() as u64;

    let configured = crate::http::rate_limit_redis::redis_url_configured();
    let enabled = crate::http::rate_limit_redis::is_enabled();
    let required = crate::http::rate_limit_redis::distributed_state_required();
    let op = if enabled {
        Some(crate::http::rate_limit_redis::incr_ask_user_strict(user_id).await)
    } else {
        None
    };
    match decide_redis_admit(configured, enabled, op, required, limit) {
        RedisAdmit::RateLimited => {
            tracing::warn!(
                target: "nl_query",
                user_id,
                limit,
                "Ask Weissman per-user rate limit exceeded (redis)"
            );
            return Err(ask_limited_response(60));
        }
        RedisAdmit::Unavailable => {
            tracing::error!(
                target: "nl_query",
                user_id,
                configured,
                enabled,
                required,
                "Ask Weissman rate limiter unavailable — fail-closed"
            );
            return Err(ask_store_unavailable_response());
        }
        RedisAdmit::Continue => {}
    }

    if let Err(neg) = limiter().check_key(&user_id) {
        let clock = DefaultClock::default();
        let retry = neg.wait_time_from(clock.now()).as_secs().max(1);
        tracing::warn!(
            target: "nl_query",
            user_id,
            retry,
            "Ask Weissman per-user rate limit exceeded"
        );
        return Err(ask_limited_response(retry));
    }

    let now = Instant::now();
    let mut map = history().lock().unwrap_or_else(|e| e.into_inner());
    let prior: Vec<String> = {
        let h = map.entry(user_id).or_insert_with(|| Hist {
            items: VecDeque::new(),
        });
        prune(h, now);
        h.items.iter().map(|(_, q)| q.clone()).collect()
    };
    if !evaluate_question_pattern(&prior, question).allowed {
        tracing::warn!(
            target: "nl_query",
            user_id,
            "Ask Weissman oracle/enumeration pattern blocked"
        );
        return Err(ask_limited_response(30));
    }
    let h = map.entry(user_id).or_insert_with(|| Hist {
        items: VecDeque::new(),
    });
    h.items
        .push_back((now, question.chars().take(2000).collect()));
    prune(h, now);
    Ok(())
}

fn prune(h: &mut Hist, now: Instant) {
    while let Some((t, _)) = h.items.front() {
        if now.saturating_duration_since(*t) > HISTORY_TTL {
            h.items.pop_front();
        } else {
            break;
        }
    }
    while h.items.len() > HISTORY_KEEP {
        h.items.pop_front();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternDecision {
    pub allowed: bool,
}

/// Pure detector: `history` is oldest→newest previous questions in the window.
#[must_use]
pub fn evaluate_question_pattern(history: &[String], question: &str) -> PatternDecision {
    let q = normalize(question);
    if q.is_empty() {
        return PatternDecision { allowed: true };
    }
    for prev in history.iter().rev().take(HISTORY_KEEP) {
        let p = normalize(prev);
        if p.is_empty() {
            continue;
        }
        if is_enumeration_pair(&p, &q) {
            return PatternDecision { allowed: false };
        }
        if trigram_cosine(&p, &q) >= SIMILARITY_ORACLE && one_alnum_slot_flip(&p, &q) {
            return PatternDecision { allowed: false };
        }
    }
    // Three near-duplicates in a row (template scan that doesn't hit the letter regex).
    if history.len() >= 2 {
        let last_two = &history[history.len().saturating_sub(2)..];
        let all_close = last_two.iter().all(|prev| {
            let p = normalize(prev);
            trigram_cosine(&p, &q) >= 0.92
        });
        if all_close
            && last_two
                .iter()
                .any(|prev| one_alnum_slot_flip(&normalize(prev), &q))
        {
            return PatternDecision { allowed: false };
        }
    }
    PatternDecision { allowed: true }
}

fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_alphanumeric() {
            for lc in c.to_lowercase() {
                out.push(lc);
            }
            prev_space = false;
        } else if !prev_space {
            out.push(' ');
            prev_space = true;
        }
    }
    out.trim().to_string()
}

fn is_enumeration_pair(prev: &str, next: &str) -> bool {
    match (probe_slot(prev), probe_slot(next)) {
        (Some((t1, s1)), Some((t2, s2))) if t1 == t2 && s1 != s2 => slots_sequential(&s1, &s2),
        _ => one_alnum_slot_flip(prev, next) && looks_like_membership_probe(next),
    }
}

fn looks_like_membership_probe(s: &str) -> bool {
    const HINTS: &[&str] = &[
        "starts with",
        "start with",
        "beginning with",
        "begins with",
        "named",
        "name is",
        "client named",
        "לקוח",
        "מתחיל",
        "ששמו",
        "exists",
        "is there",
        "any client",
        "any customer",
    ];
    HINTS.iter().any(|h| s.contains(h))
}

fn probe_slot(s: &str) -> Option<(String, String)> {
    const PREFIXES: &[&str] = &[
        "starts with ",
        "start with ",
        "beginning with ",
        "begins with ",
        "named ",
        "name is ",
        "client named ",
        "מתחיל ב ",
        "מתחילה ב ",
        "מתחיל ב",
        "מתחילה ב",
        "ששמו ",
    ];
    for pfx in PREFIXES {
        if let Some(idx) = s.find(pfx) {
            let rest = s[idx + pfx.len()..].trim_start();
            let slot: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric())
                .take(2)
                .collect();
            if slot.chars().count() == 1 {
                return Some((format!("{pfx}{{slot}}"), slot));
            }
        }
    }
    None
}

fn slots_sequential(a: &str, b: &str) -> bool {
    let (Some(ca), Some(cb)) = (a.chars().next(), b.chars().next()) else {
        return false;
    };
    if ca.is_ascii_alphabetic() && cb.is_ascii_alphabetic() {
        let da = ca.to_ascii_lowercase() as i32;
        let db = cb.to_ascii_lowercase() as i32;
        return (db - da).abs() == 1;
    }
    if ca.is_ascii_digit() && cb.is_ascii_digit() {
        return (cb as i32 - ca as i32).abs() == 1;
    }
    false
}

fn one_alnum_slot_flip(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let ac: Vec<char> = a.chars().collect();
    let bc: Vec<char> = b.chars().collect();
    if ac.len() != bc.len() {
        // Allow "… a" vs "… b" after normalize (same length usually).
        return false;
    }
    let mut diffs = 0u32;
    for (x, y) in ac.iter().zip(bc.iter()) {
        if x != y {
            if !x.is_alphanumeric() || !y.is_alphanumeric() {
                return false;
            }
            diffs += 1;
            if diffs > 1 {
                return false;
            }
        }
    }
    diffs == 1
}

fn trigram_cosine(a: &str, b: &str) -> f64 {
    let ta = trigrams(a);
    let tb = trigrams(b);
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for v in ta.values() {
        na += (*v as f64) * (*v as f64);
    }
    for v in tb.values() {
        nb += (*v as f64) * (*v as f64);
    }
    for (k, va) in &ta {
        if let Some(vb) = tb.get(k) {
            dot += (*va as f64) * (*vb as f64);
        }
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

fn trigrams(s: &str) -> HashMap<String, u32> {
    let padded = format!("  {s}  ");
    let ch: Vec<char> = padded.chars().collect();
    let mut m = HashMap::new();
    if ch.len() < 3 {
        return m;
    }
    for i in 0..=ch.len() - 3 {
        let g: String = ch[i..i + 3].iter().collect();
        *m.entry(g).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_unrelated_analyst_questions() {
        let hist = ["show me critical kev findings"];
        let hist: Vec<String> = hist.iter().map(|s| s.to_string()).collect();
        assert!(evaluate_question_pattern(&hist, "top 20 vulnerabilities by epss").allowed);
        assert!(evaluate_question_pattern(&[], "is there a crown jewel asset").allowed);
    }

    #[test]
    fn blocks_starts_with_letter_walk() {
        let hist = vec!["is there a client whose name starts with A?".to_string()];
        let d = evaluate_question_pattern(&hist, "is there a client whose name starts with B?");
        assert!(!d.allowed);
    }

    #[test]
    fn blocks_hebrew_letter_walk() {
        let hist = vec!["האם יש לקוח ששמו מתחיל ב A".to_string()];
        let d = evaluate_question_pattern(&hist, "האם יש לקוח ששמו מתחיל ב B");
        assert!(!d.allowed);
    }

    #[test]
    fn blocks_one_char_membership_flip() {
        let hist = vec!["is there any client named a".to_string()];
        let d = evaluate_question_pattern(&hist, "is there any client named b");
        assert!(!d.allowed);
    }

    #[test]
    fn ask_per_minute_never_exceeds_ten() {
        assert!(ask_per_minute().get() <= 10);
        assert_eq!(ASK_PER_MINUTE_CAP, 10);
    }

    #[test]
    fn sequential_slots() {
        assert!(slots_sequential("a", "b"));
        assert!(slots_sequential("b", "a"));
        assert!(slots_sequential("1", "2"));
        assert!(!slots_sequential("a", "c"));
        assert!(!slots_sequential("a", "1"));
    }

    #[test]
    fn ask_redis_acquire_timeout_is_fifty_ms() {
        assert_eq!(
            crate::http::rate_limit_redis::ASK_REDIS_ACQUIRE_TIMEOUT_MS,
            50
        );
    }

    #[test]
    fn redis_outage_is_fail_closed_when_configured() {
        use crate::http::rate_limit_redis::StrictOp;
        assert_eq!(
            decide_redis_admit(true, true, Some(StrictOp::Unavailable), false, 10),
            RedisAdmit::Unavailable
        );
        assert_eq!(
            decide_redis_admit(true, false, None, false, 10),
            RedisAdmit::Unavailable
        );
        assert_eq!(
            decide_redis_admit(true, true, Some(StrictOp::Ok(11)), false, 10),
            RedisAdmit::RateLimited
        );
        assert_eq!(
            decide_redis_admit(true, true, Some(StrictOp::Ok(3)), false, 10),
            RedisAdmit::Continue
        );
        assert_eq!(
            decide_redis_admit(false, false, None, false, 10),
            RedisAdmit::Continue
        );
        assert_eq!(
            decide_redis_admit(false, false, None, true, 10),
            RedisAdmit::Unavailable
        );
    }
}
