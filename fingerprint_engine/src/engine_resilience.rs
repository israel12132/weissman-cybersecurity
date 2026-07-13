//! Cross-cutting engine execution hardening — applied to every engine, every run.
//!
//! Outside-the-box autonomy without faking anything:
//!   * **Panic isolation** — an engine that panics is caught (`catch_unwind`); it never aborts the
//!     job, the batch, or the other engines. Everyone keeps running their own work.
//!   * **Adaptive multi-strategy retry** — on a *real execution failure* (error status, panic, or
//!     timeout) the engine is retried against alternate target variants (scheme swap, `www` toggle)
//!     until one works or the strategies are exhausted. A clean "no live signal" (`ok` with empty
//!     findings) is a SUCCESS and is never retried — that would manufacture noise.
//!   * **Per-attempt timeout** — a hung engine can't stall the pipeline.
//!   * **Per-engine telemetry** — attempts, winning strategy, elapsed, recovered, status — surfaced
//!     to the job result and metrics so operators can see exactly what every engine did.
//!
//! The core is generic over the engine future, so it is fully unit-tested with mock engines (no DB,
//! no network). The live wiring in `async_job_executor` passes a closure that calls
//! `engine_dispatch::run_engine`.

use crate::engine_result::EngineResult;
use futures::FutureExt;
use serde::Serialize;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

/// Default per-attempt wall-clock budget for one engine strategy.
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(45);

/// Per-engine execution telemetry (surfaced to the job result + metrics + tracing).
#[derive(Debug, Clone, Serialize)]
pub struct EngineExecTelemetry {
    pub engine_id: String,
    pub attempts: u32,
    /// The target variant that produced the returned result, or `"exhausted"`.
    pub strategy: String,
    pub elapsed_ms: u64,
    /// `ok` | `error` | `panic` | `timeout`.
    pub status: String,
    /// True when the engine only succeeded after more than one attempt.
    pub recovered: bool,
    pub error: Option<String>,
    /// Classification of the last failure (`waf`|`timeout`|`dns`|`conn_reset`|`generic`),
    /// or `None` when the first attempt succeeded cleanly. Lets the operator / next
    /// scheduler pass react to *why* an engine struggled, not just that it did.
    pub failure_class: Option<String>,
}

impl EngineExecTelemetry {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "attempts": self.attempts,
            "strategy": self.strategy,
            "elapsed_ms": self.elapsed_ms,
            "status": self.status,
            "recovered": self.recovered,
            "error": self.error,
            "failure_class": self.failure_class,
        })
    }
}

/// Only genuine execution failures are retried. A successful run that simply observed no signal
/// (`ok` with empty findings) must NOT be retried.
pub fn should_retry_status(status: &str) -> bool {
    status.eq_ignore_ascii_case("error")
}

/// Upper bound on how far an attempt timeout can be widened after repeated timeouts, so a
/// genuinely hung target can't stall the pipeline indefinitely.
const MAX_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(180);

/// Why an attempt failed. The retry loop uses this to *escalate* rather than blindly re-run
/// the same request against a string-permuted target (the previous behaviour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// WAF / rate-limit / edge block (403/429/503, Cloudflare, captcha, "blocked").
    Waf,
    /// Attempt exceeded its wall-clock budget.
    Timeout,
    /// DNS resolution failure (host may only differ by scheme/`www` variant).
    Dns,
    /// TCP reset / refused / broken pipe.
    ConnReset,
    /// Anything else.
    Generic,
}

impl FailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureClass::Waf => "waf",
            FailureClass::Timeout => "timeout",
            FailureClass::Dns => "dns",
            FailureClass::ConnReset => "conn_reset",
            FailureClass::Generic => "generic",
        }
    }
}

/// Passed to each retry attempt so the engine can *act* on why the previous attempt failed
/// rather than blindly re-running. `force_ghost_network` is set after a WAF/rate-limit block
/// so the next attempt turns on the Ghost Network (identity morphing + jitter + proxy swarm).
#[derive(Debug, Clone, Copy, Default)]
pub struct EscalationHint {
    pub attempt: u32,
    pub force_ghost_network: bool,
}

/// Classify a failed attempt from its status + message. Mirrors the heuristics in
/// `stealth::is_waf_or_rate_limit` for the WAF case so both layers agree on what a block is.
pub fn classify_failure(status: &str, message: &str) -> FailureClass {
    if status.eq_ignore_ascii_case("timeout") {
        return FailureClass::Timeout;
    }
    let m = message.to_ascii_lowercase();
    if m.contains("403")
        || m.contains("429")
        || m.contains("503")
        || m.contains("rate limit")
        || m.contains("rate-limit")
        || m.contains("too many requests")
        || m.contains("forbidden")
        || m.contains("blocked")
        || m.contains("cloudflare")
        || m.contains("captcha")
        || m.contains("access denied")
        || m.contains("web application firewall")
        || m.contains("waf")
    {
        return FailureClass::Waf;
    }
    if m.contains("dns")
        || m.contains("name resolution")
        || m.contains("no such host")
        || m.contains("failed to lookup")
        || m.contains("name or service not known")
    {
        return FailureClass::Dns;
    }
    if m.contains("connection reset")
        || m.contains("connection refused")
        || m.contains("reset by peer")
        || m.contains("broken pipe")
    {
        return FailureClass::ConnReset;
    }
    FailureClass::Generic
}

/// Escalate retry behaviour based on *why* the last attempt failed, instead of re-running the
/// same request against a string-permuted target. Widens the per-attempt budget on timeouts and
/// records WAF blocks; the WAF case ALSO flips [`EscalationHint::force_ghost_network`] for the
/// next attempt (applied by the caller's closure via `engine_dispatch::apply_ghost_escalation`).
fn escalate_for(class: FailureClass, current_timeout: &mut Duration) {
    match class {
        FailureClass::Timeout => {
            *current_timeout = current_timeout.saturating_mul(2).min(MAX_ATTEMPT_TIMEOUT);
        }
        FailureClass::Waf => {
            metrics::counter!("weissman_engine_waf_block_total").increment(1);
        }
        // Dns is already addressed by the scheme/`www` target variants; ConnReset/Generic
        // fall through to the next strategy unchanged.
        FailureClass::Dns | FailureClass::ConnReset | FailureClass::Generic => {}
    }
}

fn add_variant(out: &mut Vec<String>, s: String) {
    if !s.is_empty() && !out.contains(&s) {
        out.push(s);
    }
}

/// Ordered, de-duplicated list of target variants to try ("many ways until it succeeds"):
/// original → scheme swap (https↔http) → `www` toggle. Capped to keep retries bounded.
pub fn target_strategies(target: &str) -> Vec<String> {
    let t = target.trim();
    let mut out = Vec::new();
    add_variant(&mut out, t.to_string());

    if let Some(rest) = t.strip_prefix("https://") {
        add_variant(&mut out, format!("http://{rest}"));
    } else if let Some(rest) = t.strip_prefix("http://") {
        add_variant(&mut out, format!("https://{rest}"));
    }

    let (scheme, host_path) = match t.find("://") {
        Some(i) => (&t[..i + 3], &t[i + 3..]),
        None => ("", t),
    };
    if let Some(stripped) = host_path.strip_prefix("www.") {
        add_variant(&mut out, format!("{scheme}{stripped}"));
    } else {
        add_variant(&mut out, format!("{scheme}www.{host_path}"));
    }

    out.truncate(5);
    out
}

fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    "opaque panic payload".to_string()
}

/// Run an engine with panic isolation, per-attempt timeout, and adaptive multi-strategy retry.
///
/// `run(variant, hint)` produces the engine future for a given target variant; it is invoked
/// once per strategy until one returns a non-error result (success, including a clean empty
/// result) or all strategies are exhausted. `hint` lets the caller escalate evasion after a
/// WAF/rate-limit block (see [`EscalationHint`]). Never panics or times out the caller.
pub async fn run_with_resilience<F, Fut>(
    engine_id: &str,
    target: &str,
    attempt_timeout: Duration,
    mut run: F,
) -> (EngineResult, EngineExecTelemetry)
where
    F: FnMut(String, EscalationHint) -> Fut,
    Fut: Future<Output = EngineResult> + Send,
{
    let strategies = target_strategies(target);
    let start = Instant::now();
    let mut attempts: u32 = 0;
    let mut last_error: Option<String> = None;
    let mut last_status = String::from("error");
    let mut last_class: Option<FailureClass> = None;
    // Adaptive per-attempt budget: repeated timeouts widen it (up to a cap) instead of
    // hammering the same too-short deadline against a slow-but-alive target.
    let mut current_timeout = attempt_timeout;

    for variant in &strategies {
        attempts += 1;
        metrics::counter!("weissman_engine_attempt_total").increment(1);
        // After a WAF/rate-limit block, tell the next attempt to go stealthy.
        let hint = EscalationHint {
            attempt: attempts,
            force_ghost_network: matches!(last_class, Some(FailureClass::Waf)),
        };
        let fut = run(variant.clone(), hint);
        match tokio::time::timeout(current_timeout, AssertUnwindSafe(fut).catch_unwind()).await {
            Ok(Ok(result)) => {
                if should_retry_status(&result.status) {
                    let class = classify_failure(&result.status, &result.message);
                    escalate_for(class, &mut current_timeout);
                    last_error = Some(result.message.clone());
                    last_status = String::from("error");
                    last_class = Some(class);
                    continue;
                }
                let telem = EngineExecTelemetry {
                    engine_id: engine_id.to_string(),
                    attempts,
                    strategy: variant.clone(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    status: String::from("ok"),
                    recovered: attempts > 1,
                    error: None,
                    failure_class: last_class.map(|c| c.as_str().to_string()),
                };
                if telem.recovered {
                    metrics::counter!("weissman_engine_recovered_total").increment(1);
                }
                return (result, telem);
            }
            Ok(Err(payload)) => {
                let msg = panic_message(payload);
                let class = classify_failure("panic", &msg);
                escalate_for(class, &mut current_timeout);
                last_error = Some(msg);
                last_status = String::from("panic");
                last_class = Some(class);
                metrics::counter!("weissman_engine_panic_total").increment(1);
                continue;
            }
            Err(_) => {
                last_error = Some(format!(
                    "attempt timed out after {}ms",
                    current_timeout.as_millis()
                ));
                last_status = String::from("timeout");
                last_class = Some(FailureClass::Timeout);
                escalate_for(FailureClass::Timeout, &mut current_timeout);
                metrics::counter!("weissman_engine_timeout_total").increment(1);
                continue;
            }
        }
    }

    let err = last_error.unwrap_or_else(|| "engine failed".to_string());
    let telem = EngineExecTelemetry {
        engine_id: engine_id.to_string(),
        attempts,
        strategy: String::from("exhausted"),
        elapsed_ms: start.elapsed().as_millis() as u64,
        status: last_status,
        recovered: false,
        error: Some(err.clone()),
        failure_class: last_class.map(|c| c.as_str().to_string()),
    };
    metrics::counter!("weissman_engine_failed_total").increment(1);
    (
        EngineResult::error(format!(
            "engine '{engine_id}' failed after {attempts} strategy attempt(s): {err}"
        )),
        telem,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn strategies_swap_scheme_and_toggle_www() {
        let s = target_strategies("https://example.com");
        assert_eq!(s[0], "https://example.com");
        assert!(s.contains(&"http://example.com".to_string()));
        assert!(s.contains(&"https://www.example.com".to_string()));

        let s2 = target_strategies("www.example.com");
        assert_eq!(s2[0], "www.example.com");
        assert!(s2.contains(&"example.com".to_string()));

        // No duplicates.
        let mut sorted = s.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), s.len());
    }

    #[test]
    fn retry_only_on_error_status() {
        assert!(should_retry_status("error"));
        assert!(!should_retry_status("ok"));
    }

    #[tokio::test]
    async fn recovers_on_a_later_strategy() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let (result, telem) = run_with_resilience(
            "flaky",
            "https://example.com",
            Duration::from_secs(2),
            move |_variant, _hint| {
                let n = c.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        EngineResult::error("transient connection reset")
                    } else {
                        EngineResult::ok(vec![serde_json::json!({"k": "v"})], "ok")
                    }
                }
            },
        )
        .await;
        assert_eq!(result.status, "ok");
        assert_eq!(telem.attempts, 2);
        assert!(telem.recovered);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn empty_ok_is_success_and_not_retried() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let (result, telem) = run_with_resilience(
            "quiet",
            "example.com",
            Duration::from_secs(2),
            move |_v, _hint| {
                c.fetch_add(1, Ordering::SeqCst);
                async move { EngineResult::ok(vec![], "no live signal observed") }
            },
        )
        .await;
        assert_eq!(result.status, "ok");
        assert_eq!(telem.attempts, 1);
        assert!(!telem.recovered);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panic_is_isolated_not_propagated() {
        let (result, telem) = run_with_resilience(
            "panicky",
            "example.com",
            Duration::from_secs(2),
            move |_v, _hint| async move {
                panic!("engine blew up");
                #[allow(unreachable_code)]
                EngineResult::ok(vec![], "")
            },
        )
        .await;
        // The caller survives; result is a clean error, status reflects the panic.
        assert_eq!(result.status, "error");
        assert_eq!(telem.status, "panic");
        assert!(telem.attempts >= 1);
    }

    #[tokio::test]
    async fn hung_engine_times_out_per_attempt() {
        let (result, telem) = run_with_resilience(
            "hung",
            "example.com",
            Duration::from_millis(40),
            move |_v, _hint| async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                EngineResult::ok(vec![], "")
            },
        )
        .await;
        assert_eq!(result.status, "error");
        assert_eq!(telem.status, "timeout");
    }

    #[test]
    fn classify_failure_maps_signals() {
        assert_eq!(classify_failure("timeout", ""), FailureClass::Timeout);
        assert_eq!(
            classify_failure("error", "HTTP 403 Forbidden"),
            FailureClass::Waf
        );
        assert_eq!(
            classify_failure("error", "429 Too Many Requests"),
            FailureClass::Waf
        );
        assert_eq!(
            classify_failure("error", "request blocked by Cloudflare"),
            FailureClass::Waf
        );
        assert_eq!(
            classify_failure("error", "dns error: no such host"),
            FailureClass::Dns
        );
        assert_eq!(
            classify_failure("error", "connection reset by peer"),
            FailureClass::ConnReset
        );
        assert_eq!(
            classify_failure("error", "something unexpected"),
            FailureClass::Generic
        );
    }

    #[test]
    fn timeout_escalation_widens_and_caps_budget() {
        let mut t = Duration::from_secs(45);
        escalate_for(FailureClass::Timeout, &mut t);
        assert_eq!(t, Duration::from_secs(90));
        for _ in 0..10 {
            escalate_for(FailureClass::Timeout, &mut t);
        }
        assert_eq!(t, MAX_ATTEMPT_TIMEOUT, "timeout budget must be capped");
        // A WAF block records a counter but does not widen the budget.
        let mut t2 = Duration::from_secs(45);
        escalate_for(FailureClass::Waf, &mut t2);
        assert_eq!(t2, Duration::from_secs(45));
    }

    #[tokio::test]
    async fn failure_class_surfaced_in_telemetry() {
        let (result, telem) = run_with_resilience(
            "blocked",
            "example.com",
            Duration::from_secs(2),
            move |_v, _hint| async move { EngineResult::error("HTTP 403 blocked by WAF") },
        )
        .await;
        assert_eq!(result.status, "error");
        assert_eq!(telem.failure_class.as_deref(), Some("waf"));
    }

    #[tokio::test]
    async fn waf_block_forces_ghost_network_on_next_attempt() {
        let hints: Arc<std::sync::Mutex<Vec<bool>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let h = hints.clone();
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let _ = run_with_resilience(
            "wafed",
            "https://example.com",
            Duration::from_secs(2),
            move |_v, hint| {
                h.lock().unwrap().push(hint.force_ghost_network);
                let n = c.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        EngineResult::error("HTTP 403 blocked by WAF")
                    } else {
                        EngineResult::ok(vec![], "ok")
                    }
                }
            },
        )
        .await;
        let recorded = hints.lock().unwrap().clone();
        // First attempt: no prior failure. Second attempt (after the WAF block): ghost network.
        assert_eq!(recorded.first(), Some(&false));
        assert_eq!(recorded.get(1), Some(&true));
    }
}
