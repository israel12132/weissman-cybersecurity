//! Isolate blocking filesystem / CPU-heavy work off the Axum worker threads.
//!
//! Tokio worker threads run the event loop. `std::fs` and heavy math on those
//! threads stall every other connection sharing the worker. Always go through
//! [`spawn_blocking`].

use std::future::Future;

/// Run `f` on Tokio's blocking thread pool. The join error is mapped to a string
/// so HTTP handlers can return 500 without panicking the worker.
pub fn spawn_blocking<F, R>(f: F) -> impl Future<Output = Result<R, String>>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    async move {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| format!("spawn_blocking join: {e}"))
    }
}

/// Linux RSS from `/proc/self/statm`, cached 5s, file read on the blocking pool.
pub async fn resident_set_kb() -> Option<u64> {
    #[cfg(not(target_os = "linux"))]
    {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        static CACHE_VAL: AtomicU64 = AtomicU64::new(0);
        static CACHE_AT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
        let lock = CACHE_AT.get_or_init(|| Mutex::new(None));
        if let Ok(guard) = lock.lock() {
            if let Some(when) = *guard {
                if when.elapsed() < Duration::from_secs(5) {
                    let v = CACHE_VAL.load(Ordering::Relaxed);
                    if v > 0 {
                        return Some(v);
                    }
                }
            }
        }
        let kb = spawn_blocking(read_statm_kb).await.ok().flatten()?;
        CACHE_VAL.store(kb, Ordering::Relaxed);
        if let Ok(mut guard) = lock.lock() {
            *guard = Some(Instant::now());
        }
        Some(kb)
    }
}

#[cfg(target_os = "linux")]
fn read_statm_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let mut it = s.split_whitespace();
    let _vsize = it.next()?;
    let resident_pages: u64 = it.next()?.parse().ok()?;
    Some(resident_pages.saturating_mul(4096) / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_blocking_returns_value() {
        let n = spawn_blocking(|| 7 + 8).await.expect("join");
        assert_eq!(n, 15);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rss_is_nonzero_on_linux() {
        let kb = resident_set_kb().await.expect("statm");
        assert!(kb > 0);
    }
}
