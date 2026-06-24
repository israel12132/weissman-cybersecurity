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
        })
    }
}

/// Only genuine execution failures are retried. A successful run that simply observed no signal
/// (`ok` with empty findings) must NOT be retried.
pub fn should_retry_status(status: &str) -> bool {
    status.eq_ignore_ascii_case("error")
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
/// `run(variant)` produces the engine future for a given target variant; it is invoked once per
/// strategy until one returns a non-error result (success, including a clean empty result) or all
/// strategies are exhausted. Never panics or times out the caller.
pub async fn run_with_resilience<F, Fut>(
    engine_id: &str,
    target: &str,
    attempt_timeout: Duration,
    mut run: F,
) -> (EngineResult, EngineExecTelemetry)
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = EngineResult> + Send,
{
    let strategies = target_strategies(target);
    let start = Instant::now();
    let mut attempts: u32 = 0;
    let mut last_error: Option<String> = None;
    let mut last_status = String::from("error");

    for variant in &strategies {
        attempts += 1;
        metrics::counter!("weissman_engine_attempt_total").increment(1);
        let fut = run(variant.clone());
        match tokio::time::timeout(attempt_timeout, AssertUnwindSafe(fut).catch_unwind()).await {
            Ok(Ok(result)) => {
                if should_retry_status(&result.status) {
                    last_error = Some(result.message.clone());
                    last_status = String::from("error");
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
                };
                if telem.recovered {
                    metrics::counter!("weissman_engine_recovered_total").increment(1);
                }
                return (result, telem);
            }
            Ok(Err(payload)) => {
                last_error = Some(panic_message(payload));
                last_status = String::from("panic");
                metrics::counter!("weissman_engine_panic_total").increment(1);
                continue;
            }
            Err(_) => {
                last_error = Some(format!(
                    "attempt timed out after {}ms",
                    attempt_timeout.as_millis()
                ));
                last_status = String::from("timeout");
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
            move |_variant| {
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
        let (result, telem) =
            run_with_resilience("quiet", "example.com", Duration::from_secs(2), move |_v| {
                c.fetch_add(1, Ordering::SeqCst);
                async move { EngineResult::ok(vec![], "no live signal observed") }
            })
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
            move |_v| async move {
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
            move |_v| async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                EngineResult::ok(vec![], "")
            },
        )
        .await;
        assert_eq!(result.status, "error");
        assert_eq!(telem.status, "timeout");
    }
}
