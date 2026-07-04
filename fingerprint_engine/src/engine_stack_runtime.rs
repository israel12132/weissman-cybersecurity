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

/// Execute `future_fn` on a dedicated thread with an enlarged stack and its own
/// current-thread Tokio runtime (required — the worker's Handle is not valid off-thread).
pub async fn run_on_large_stack<F, Fut, T>(future_fn: F) -> T
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let stack_size = large_stack_bytes();
    std::thread::Builder::new()
        .name("weissman-engine".into())
        .stack_size(stack_size)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("weissman-engine runtime");
            let _ = tx.send(rt.block_on(future_fn()));
        })
        .expect("spawn large-stack engine thread");

    rx.await
        .expect("large-stack engine thread dropped without sending result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn large_stack_thread_runs_future() {
        let n = run_on_large_stack(|| async { 42 }).await;
        assert_eq!(n, 42);
    }
}
