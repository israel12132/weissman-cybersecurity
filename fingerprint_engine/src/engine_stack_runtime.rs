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

/// Stack size for the dedicated engine thread.
///
/// Must exceed the runtime worker-thread stack, or moving work here makes the overflow it exists
/// to prevent MORE likely rather than less. Under the shipped defaults it did exactly that: the
/// worker builds its runtime with `WEISSMAN_WORKER_THREAD_STACK_MB` (default 64 MiB) while this
/// defaulted to 32 MiB, so every heavy job was moved from a 64 MiB stack onto a 32 MiB one — the
/// "large stack" protection inverted.
///
/// The floor is therefore computed against the runtime stack rather than being a bare constant,
/// so raising one cannot silently invert the other again.
fn large_stack_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| {
        // Same env var and default the worker uses to size its runtime threads.
        let runtime_stack = std::env::var("WEISSMAN_WORKER_THREAD_STACK_MB")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 2)
            .unwrap_or(64)
            * 1024
            * 1024;
        // Double the runtime stack: the whole point is headroom for recursion that a runtime
        // thread cannot survive.
        let floor = runtime_stack.saturating_mul(2);

        match std::env::var("WEISSMAN_ENGINE_STACK_BYTES")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 2 * 1024 * 1024)
        {
            Some(explicit) if explicit < runtime_stack => {
                eprintln!(
                    "[Weissman][engine_stack] WEISSMAN_ENGINE_STACK_BYTES={explicit} is smaller \
                     than the runtime thread stack ({runtime_stack}); raising to {floor} — a \
                     'large stack' below the stack it replaces makes overflow more likely, not less"
                );
                floor
            }
            Some(explicit) => explicit,
            None => floor,
        }
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

/// Like [`run_on_large_stack`], but abandons the future when `cancel` fires. Returns `None` if it
/// was cancelled before producing a value.
///
/// `tokio::task::AbortHandle::abort()` cannot stop this work. `run_on_large_stack` hands the
/// future to a raw OS thread and only awaits a oneshot, so aborting the *tokio task* that awaits
/// it merely drops the receiver: the thread keeps running the engine to completion, holding its
/// DB connections and outbound sockets. On a heavy-job timeout the worker did exactly that — it
/// gave up waiting, requeued the job, and a second worker started the same scan while the first
/// copy was still executing, invisible and unstoppable, until the process exited.
///
/// A future cannot be interrupted mid-poll, so this cancels at the next `.await` — which for
/// scan engines means the next network or database boundary, i.e. almost immediately in practice.
/// Dropping the future there runs its destructors, releasing connections properly instead of
/// abandoning them.
pub async fn run_on_large_stack_cancellable<F, Fut, T>(
    future_fn: F,
    cancel: oneshot::Receiver<()>,
) -> Option<T>
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
            let out = handle.block_on(async move {
                tokio::select! {
                    v = future_fn() => Some(v),
                    // A dropped sender (the caller went away) also means "stop".
                    _ = cancel => None,
                }
            });
            let _ = tx.send(out);
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

    /// The whole point of the cancellable variant: the engine must actually STOP.
    ///
    /// `abort()` on the awaiting task cannot do this — the work lives on a raw OS thread — so a
    /// timed-out heavy job kept running while a second worker started the same scan.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellable_stops_the_engine_thread_at_its_next_await() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let ran_past_cancel = Arc::new(AtomicBool::new(false));
        let flag = ran_past_cancel.clone();
        let (cancel_tx, cancel_rx) = oneshot::channel();

        let task = tokio::spawn(async move {
            run_on_large_stack_cancellable(
                move || async move {
                    // Await point: where cancellation can land.
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    flag.store(true, Ordering::SeqCst);
                    7u32
                },
                cancel_rx,
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        cancel_tx.send(()).expect("send cancel");

        let out = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("cancellation must return promptly, not after the 30s sleep")
            .expect("join");

        assert_eq!(out, None, "a cancelled run must not yield a value");
        assert!(
            !ran_past_cancel.load(Ordering::SeqCst),
            "the future continued past its await after cancellation — the engine was not stopped"
        );
    }

    /// Cancellation must not truncate work that already finished.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellable_returns_the_value_when_not_cancelled() {
        let (_cancel_tx, cancel_rx) = oneshot::channel();
        let out = run_on_large_stack_cancellable(|| async { 42u32 }, cancel_rx).await;
        assert_eq!(out, Some(42));
    }


    /// The engine stack must never be smaller than the runtime stack it replaces.
    #[test]
    fn engine_stack_is_never_smaller_than_the_runtime_stack() {
        // Defaults: runtime 64 MiB, engine floor 2x that.
        let runtime_default = 64 * 1024 * 1024usize;
        let got = large_stack_bytes();
        assert!(
            got >= runtime_default,
            "engine stack {got} < runtime thread stack {runtime_default} — moving a heavy job \
             here would SHRINK its stack, which is the inverse of this module's purpose"
        );
    }

}