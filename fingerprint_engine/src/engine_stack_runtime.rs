//! Run heavy engine dispatch on a dedicated OS thread with an expanded stack.
//!
//! Tokio worker threads use a modest default stack (~2 MiB). The monolithic
//! `dispatch_engine_match` future for production engines can overflow that stack
//! even when the engine logic itself is shallow. Spawning a named thread with
//! `WEISSMAN_ENGINE_STACK_BYTES` (default 32 MiB) keeps workers alive without
//! relying on process-wide `RUST_MIN_STACK`.

use std::future::Future;
use std::sync::OnceLock;
use tokio::sync::oneshot;

fn large_stack_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| {
        std::env::var("WEISSMAN_ENGINE_STACK_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n| n >= 2 * 1024 * 1024)
            .unwrap_or(32 * 1024 * 1024)
    })
}

/// Execute `future_fn` on a dedicated OS thread with an enlarged stack, driving it with
/// the **parent** runtime (via its `Handle`) rather than a throwaway per-call runtime.
///
/// Why not a fresh `current_thread` runtime here (the previous implementation): sqlx pool
/// connections are bound to the I/O reactor of the runtime that drives them. A per-call
/// runtime that is dropped when the job returns orphans every app-pool connection the job
/// opened. Those orphaned connections go back onto the pool's idle queue, but their
/// reactor is dead — so the pool's default `test_before_acquire` health ping on the next
/// acquire never completes (the ping future can never be woken), and the acquire blocks
/// for the full 30s `acquire_timeout` before failing with "pool timed out while waiting
/// for an open connection" *even when num_idle > 0 and the pool is far below max*. That is
/// the real cause of the worker claim/reserve stalls (Postgres also logs "unexpected EOF
/// ... with an open transaction" for the abandoned sockets). It is finding- and
/// LLM-independent, which is why bounding the background persistence / metering spawns did
/// not fix it.
///
/// Driving the future with the parent runtime's `Handle` keeps every connection bound to
/// the persistent worker reactor (never orphaned) while still giving the deep engine
/// future its 32 MiB stack. Requires the parent runtime to be multi-threaded (the worker
/// is `#[tokio::main]`, i.e. multi-thread) so a second thread calling `Handle::block_on`
/// cannot deadlock the reactor.
pub async fn run_on_large_stack<F, Fut, T>(future_fn: F) -> T
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handle = tokio::runtime::Handle::current();
    let (tx, rx) = oneshot::channel();
    let stack_size = large_stack_bytes();
    std::thread::Builder::new()
        .name("weissman-engine".into())
        .stack_size(stack_size)
        .spawn(move || {
            // Plain OS thread (not a runtime worker), so `Handle::block_on` is allowed; it
            // drives the future here while the parent runtime services connection I/O.
            let _ = tx.send(handle.block_on(async move { future_fn().await }));
        })
        .expect("spawn large-stack engine thread");

    rx.await
        .expect("large-stack engine thread dropped without sending result")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Multi-thread flavor is required: `run_on_large_stack` drives the future with the
    // parent runtime's `Handle` from a second thread, which would deadlock a
    // single-threaded runtime (the worker is `#[tokio::main]` = multi-thread).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_stack_thread_runs_future() {
        let n = run_on_large_stack(|| async { 42 }).await;
        assert_eq!(n, 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nested_large_stack_runs() {
        let n = run_on_large_stack(|| async { run_on_large_stack(|| async { 7 }).await + 1 }).await;
        assert_eq!(n, 8);
    }

    // Regression guard for the pool-affinity fix. A fire-and-forget task spawned inside
    // `run_on_large_stack` must run to completion on the PARENT runtime after the call
    // returns. With the previous per-call `current_thread` runtime it was cancelled when
    // that runtime was dropped — the same mechanism that orphaned pooled connections and
    // stalled the worker's claim/reserve loop. This must NOT need a DB: it isolates the
    // runtime-affinity property directly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detached_tasks_survive_after_return() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        run_on_large_stack(move || async move {
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                d.store(true, Ordering::SeqCst);
            });
            // return immediately — the spawned task outlives this future
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        assert!(
            done.load(Ordering::SeqCst),
            "a fire-and-forget task spawned inside run_on_large_stack was cancelled when the \
             call returned; it must complete on the parent runtime (pool-affinity fix)"
        );
    }
}
