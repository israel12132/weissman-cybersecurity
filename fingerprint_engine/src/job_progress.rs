//! In-process physical-progress clock for the job currently executing on this worker.
//!
//! The keep-alive thread extends the Redis lease every 10s. That is **not** progress.
//! Engines, fuzz probes, and scan chunks call [`mark`] when they did real work (HTTP
//! sent/received, engine started/finished, chunk enqueued). If nothing marks for 60s
//! the worker Force-Aborts the job.
//!
//! Uses a tokio task-local so deep call sites (fuzzer waves, `run_engine`) do not need
//! the job id threaded through every signature.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

tokio::task_local! {
    static CURRENT: Arc<JobProgress>;
}

/// Monotonic progress clock for one claimed job.
#[derive(Debug)]
pub struct JobProgress {
    started: Instant,
    last_ms: AtomicU64,
    last_note: Mutex<String>,
}

impl JobProgress {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            last_ms: AtomicU64::new(0),
            last_note: Mutex::new("job_started".into()),
        })
    }

    /// Record physical progress. Cheap; safe to call per fuzz probe.
    pub fn mark(&self, note: &str) {
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::SeqCst);
        if let Ok(mut g) = self.last_note.lock() {
            let n = note.trim();
            if !n.is_empty() {
                *g = n.chars().take(200).collect();
            }
        }
    }

    #[must_use]
    pub fn age_secs(&self) -> u64 {
        let last = self.last_ms.load(Ordering::SeqCst);
        let now = self.started.elapsed().as_millis() as u64;
        now.saturating_sub(last) / 1000
    }

    /// Milliseconds since job start of the last physical mark (for DB flush dedup).
    #[must_use]
    pub fn last_mark_ms(&self) -> u64 {
        self.last_ms.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn last_note(&self) -> String {
        self.last_note
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "job_started".into())
    }
}

/// Bind `progress` as the current job's clock for the duration of `fut`.
pub async fn scope<F, R>(progress: Arc<JobProgress>, fut: F) -> R
where
    F: Future<Output = R>,
{
    CURRENT.scope(progress, fut).await
}

/// Mark physical progress on the current job, if a clock is bound.
pub fn mark(note: &str) {
    let _ = CURRENT.try_with(|p| p.mark(note));
}

/// Current job progress clock, if this task is inside [`scope`].
#[must_use]
pub fn current() -> Option<Arc<JobProgress>> {
    CURRENT.try_with(Arc::clone).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn new_clock_starts_fresh() {
        let p = JobProgress::new();
        assert!(p.age_secs() < 2);
        assert_eq!(p.last_note(), "job_started");
    }

    #[test]
    fn mark_resets_age() {
        let p = JobProgress::new();
        std::thread::sleep(Duration::from_millis(20));
        p.mark("engine:asm");
        assert_eq!(p.last_note(), "engine:asm");
        assert!(p.age_secs() < 2);
    }

    #[tokio::test]
    async fn scope_binds_task_local() {
        let p = JobProgress::new();
        scope(p.clone(), async {
            assert!(current().is_some());
            mark("fuzz_probe");
        })
        .await;
        assert_eq!(p.last_note(), "fuzz_probe");
        assert!(current().is_none());
    }

    #[test]
    fn mark_without_scope_is_a_noop() {
        mark("nobody-listening");
        assert!(current().is_none());
    }
}
