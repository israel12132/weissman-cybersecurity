//! Smart stealth scheduler — dispatch a large engine batch the way a disciplined human red-team
//! would: quietly, under the WAF radar, without hammering (DoS-ing) the target.
//!
//! When an operator says "run 200 engines", firing 200 concurrent request storms at one host trips
//! every WAF and can knock the target over — an amateur move. This module turns that one command
//! into a controlled operation:
//!
//!   * **Concurrency control** — at most `max_concurrent` engines are ever in flight against a
//!     single target; the rest wait in a dynamic queue (modelled here as fixed dispatch *lanes*).
//!   * **Rate limiting + jitter** — each lane drips sequentially with a randomised inter-request
//!     delay (base gap + jitter), so traffic never arrives in a machine-gun burst.
//!   * **Identity rotation** — every dispatch gets a rotated, realistic browser User-Agent + header
//!     set, so the batch looks like many ordinary clients rather than one scanner.
//!
//! The schedule is **deterministic given a seed** (a small seeded PRNG, not wall-clock randomness),
//! so it is fully unit-testable and reproducible; the live executor supplies a per-batch seed. This
//! module is also the single source of truth for the browser User-Agent pool, replacing the copies
//! scattered across individual engines.

use serde::Serialize;
use serde_json::{json, Value};

/// Canonical, realistic modern-desktop-browser User-Agents. One authoritative list so the whole
/// platform rotates the same believable identities instead of maintaining ad-hoc copies per engine.
pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
];

/// Rotated Accept-Language values, to vary a second fingerprintable header alongside the UA.
const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.9,fr;q=0.6",
    "en-US,en;q=0.7,de;q=0.3",
];

/// A realistic request header set for one dispatch (UA + companions), rotated by index.
#[must_use]
pub fn header_set(index: usize) -> Vec<(&'static str, String)> {
    let ua = USER_AGENTS[index % USER_AGENTS.len()];
    let lang = ACCEPT_LANGUAGES[index % ACCEPT_LANGUAGES.len()];
    let is_mobile = ua.contains("Mobile");
    vec![
        ("User-Agent", ua.to_string()),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                .to_string(),
        ),
        ("Accept-Language", lang.to_string()),
        ("Accept-Encoding", "gzip, deflate, br".to_string()),
        ("Sec-Fetch-Dest", "document".to_string()),
        ("Sec-Fetch-Mode", "navigate".to_string()),
        ("Sec-Fetch-Site", "none".to_string()),
        ("Upgrade-Insecure-Requests", "1".to_string()),
        ("Sec-Ch-Ua-Mobile", if is_mobile { "?1" } else { "?0" }.to_string()),
    ]
}

/// Stealth dispatch policy. All fields are sanitised into safe ranges by [`StealthPlan::sanitized`].
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StealthPlan {
    /// Max engines ever in flight against a single target (dynamic queue holds the rest).
    pub max_concurrent: usize,
    /// Minimum inter-dispatch delay per lane (ms).
    pub jitter_min_ms: u64,
    /// Maximum inter-dispatch delay per lane (ms).
    pub jitter_max_ms: u64,
    /// Fixed gap added to every inter-dispatch delay (ms) — the human "think time" floor.
    pub base_gap_ms: u64,
}

impl Default for StealthPlan {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            jitter_min_ms: 250,
            jitter_max_ms: 1500,
            base_gap_ms: 300,
        }
    }
}

impl StealthPlan {
    /// Clamp every field into a safe, non-degenerate range (concurrency 1..=32, sane jitter).
    #[must_use]
    pub fn sanitized(&self) -> Self {
        let max_concurrent = self.max_concurrent.clamp(1, 32);
        let jitter_min_ms = self.jitter_min_ms.min(60_000);
        let jitter_max_ms = self.jitter_max_ms.clamp(jitter_min_ms, 120_000);
        let base_gap_ms = self.base_gap_ms.min(60_000);
        Self {
            max_concurrent,
            jitter_min_ms,
            jitter_max_ms,
            base_gap_ms,
        }
    }
}

/// One scheduled engine dispatch: when to fire it, on which concurrency lane, and with which
/// rotated identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScheduledDispatch {
    /// Position in the original batch.
    pub index: usize,
    /// Concurrency lane (0..max_concurrent) — models one of the open connections to the target.
    pub lane: usize,
    /// Milliseconds after batch start when this dispatch fires.
    pub delay_ms: u64,
    /// Index into [`USER_AGENTS`] / header rotation for this dispatch.
    pub user_agent_index: usize,
}

/// Small deterministic PRNG (SplitMix64) — reproducible jitter without wall-clock randomness.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn jitter_in_range(state: &mut u64, min: u64, max: u64) -> u64 {
    if max <= min {
        return min;
    }
    min + splitmix64(state) % (max - min + 1)
}

/// Build the full drip schedule for `n` dispatches under `plan`, deterministic for `seed`.
///
/// Model: `max_concurrent` sequential lanes (a semaphore of that size). Dispatch `i` is assigned to
/// lane `i % max_concurrent`; within a lane, dispatches fire back-to-back separated by
/// `base_gap_ms + jitter`. Lanes are staggered at the start so the first wave doesn't fire all at
/// once. The result therefore never has more than `max_concurrent` engines in flight, and traffic
/// on each connection is paced like a human.
#[must_use]
pub fn schedule(n: usize, plan: &StealthPlan, seed: u64) -> Vec<ScheduledDispatch> {
    let plan = plan.sanitized();
    let lanes = plan.max_concurrent;
    let mut lane_time = vec![0u64; lanes];
    // Small deterministic per-lane start stagger so lane 0..k don't all fire at t=0.
    let mut state = seed ^ 0xA5A5_5A5A_1234_5678;
    let stagger_step = plan.base_gap_ms / (lanes.max(1) as u64) + 17;
    for (l, t) in lane_time.iter_mut().enumerate() {
        *t = (l as u64) * stagger_step;
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let lane = i % lanes;
        let delay = lane_time[lane];
        out.push(ScheduledDispatch {
            index: i,
            lane,
            delay_ms: delay,
            user_agent_index: i % USER_AGENTS.len(),
        });
        let step = plan.base_gap_ms + jitter_in_range(&mut state, plan.jitter_min_ms, plan.jitter_max_ms);
        lane_time[lane] = lane_time[lane].saturating_add(step);
    }
    out
}

/// Build the `command_center_engine` job payload for one scheduled dispatch, carrying the rotated
/// identity (headers) and stealth annotations so the worker runs it under the same cover. Pure.
#[must_use]
pub fn job_payload(
    engine_id: &str,
    target: &str,
    client_id: i64,
    batch_id: &str,
    dispatch: &ScheduledDispatch,
) -> Value {
    let headers: Vec<Value> = header_set(dispatch.user_agent_index)
        .into_iter()
        .map(|(k, v)| json!({ "name": k, "value": v }))
        .collect();
    json!({
        "engine": engine_id,
        "target": target,
        "client_id": client_id,
        "trigger": "arsenal_stealth_batch",
        "batch_id": batch_id,
        "stealth": {
            "lane": dispatch.lane,
            "delay_ms": dispatch.delay_ms,
            "headers": headers,
        },
    })
}

/// Total wall-clock the batch will take (ms) — the latest scheduled dispatch's offset.
#[must_use]
pub fn estimated_duration_ms(sched: &[ScheduledDispatch]) -> u64 {
    sched.iter().map(|d| d.delay_ms).max().unwrap_or(0)
}

/// JSON preview of how a batch of `count` engines will drip out under `plan` — for the UI to show
/// the operator the operation cadence before they commit.
#[must_use]
pub fn plan_summary(count: usize, plan: &StealthPlan, seed: u64) -> Value {
    let plan = plan.sanitized();
    let sched = schedule(count, &plan, seed);
    let eta = estimated_duration_ms(&sched);
    let waves = count.div_ceil(plan.max_concurrent.max(1));
    let sample: Vec<Value> = sched
        .iter()
        .take(12)
        .map(|d| json!({ "index": d.index, "lane": d.lane, "delay_ms": d.delay_ms, "ua": USER_AGENTS[d.user_agent_index] }))
        .collect();
    json!({
        "ok": true,
        "requested": count,
        "max_concurrent": plan.max_concurrent,
        "jitter_ms": [plan.jitter_min_ms, plan.jitter_max_ms],
        "base_gap_ms": plan.base_gap_ms,
        "waves": waves,
        "estimated_duration_ms": eta,
        "user_agents_in_rotation": USER_AGENTS.len(),
        "sample": sample,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_sanitizes_into_safe_ranges() {
        let p = StealthPlan {
            max_concurrent: 9999,
            jitter_min_ms: 5000,
            jitter_max_ms: 10,
            base_gap_ms: 999_999,
        }
        .sanitized();
        assert_eq!(p.max_concurrent, 32);
        assert!(p.jitter_max_ms >= p.jitter_min_ms);
        assert!(p.base_gap_ms <= 60_000);

        let z = StealthPlan { max_concurrent: 0, ..StealthPlan::default() }.sanitized();
        assert_eq!(z.max_concurrent, 1);
    }

    #[test]
    fn schedule_never_exceeds_max_concurrent_lanes() {
        let plan = StealthPlan { max_concurrent: 10, ..StealthPlan::default() };
        let sched = schedule(200, &plan, 42);
        assert_eq!(sched.len(), 200);
        let max_lane = sched.iter().map(|d| d.lane).max().unwrap();
        assert!(max_lane < 10, "no lane beyond max_concurrent");
        assert_eq!(sched.iter().map(|d| d.lane).collect::<std::collections::BTreeSet<_>>().len(), 10);
    }

    #[test]
    fn within_a_lane_delays_strictly_increase_by_gap_plus_jitter() {
        let plan = StealthPlan { max_concurrent: 4, jitter_min_ms: 100, jitter_max_ms: 500, base_gap_ms: 200 };
        let p = plan.sanitized();
        let sched = schedule(40, &plan, 7);
        // Group by lane, check monotonic + step bounds.
        for lane in 0..p.max_concurrent {
            let mut prev: Option<u64> = None;
            for d in sched.iter().filter(|d| d.lane == lane) {
                if let Some(pv) = prev {
                    let step = d.delay_ms - pv;
                    assert!(step >= p.base_gap_ms + p.jitter_min_ms, "step {step} below floor");
                    assert!(step <= p.base_gap_ms + p.jitter_max_ms, "step {step} above ceiling");
                }
                prev = Some(d.delay_ms);
            }
        }
    }

    #[test]
    fn schedule_is_deterministic_for_a_seed() {
        let plan = StealthPlan::default();
        assert_eq!(schedule(100, &plan, 123), schedule(100, &plan, 123));
        assert_ne!(schedule(100, &plan, 123), schedule(100, &plan, 124));
    }

    #[test]
    fn user_agents_rotate_across_the_pool() {
        let plan = StealthPlan::default();
        let sched = schedule(USER_AGENTS.len() * 2, &plan, 1);
        let distinct: std::collections::BTreeSet<usize> =
            sched.iter().map(|d| d.user_agent_index).collect();
        assert_eq!(distinct.len(), USER_AGENTS.len(), "rotation cycles the whole pool");
    }

    #[test]
    fn header_set_carries_a_rotated_ua_and_companions() {
        let h = header_set(0);
        assert!(h.iter().any(|(k, v)| *k == "User-Agent" && v == USER_AGENTS[0]));
        assert!(h.iter().any(|(k, _)| *k == "Accept-Language"));
        // Rotation actually changes the UA.
        let a = header_set(0).into_iter().find(|(k, _)| *k == "User-Agent").unwrap().1;
        let b = header_set(1).into_iter().find(|(k, _)| *k == "User-Agent").unwrap().1;
        assert_ne!(a, b);
    }

    #[test]
    fn estimated_duration_grows_with_batch_size() {
        let plan = StealthPlan::default();
        let small = estimated_duration_ms(&schedule(10, &plan, 5));
        let big = estimated_duration_ms(&schedule(200, &plan, 5));
        assert!(big > small);
    }

    #[test]
    fn job_payload_carries_engine_target_and_rotated_headers() {
        let sched = schedule(3, &StealthPlan::default(), 5);
        let p = job_payload("graphql_attack", "app.example.com", 7, "batch-1", &sched[1]);
        assert_eq!(p["engine"], "graphql_attack");
        assert_eq!(p["target"], "app.example.com");
        assert_eq!(p["client_id"], 7);
        assert_eq!(p["batch_id"], "batch-1");
        assert_eq!(p["trigger"], "arsenal_stealth_batch");
        let headers = p["stealth"]["headers"].as_array().unwrap();
        assert!(headers.iter().any(|h| h["name"] == "User-Agent"));
        assert_eq!(p["stealth"]["lane"].as_u64().unwrap(), sched[1].lane as u64);
    }

    #[test]
    fn summary_reports_waves_and_eta() {
        let s = plan_summary(200, &StealthPlan { max_concurrent: 10, ..StealthPlan::default() }, 9);
        assert_eq!(s["requested"], 200);
        assert_eq!(s["max_concurrent"], 10);
        assert_eq!(s["waves"], 20);
        assert!(s["estimated_duration_ms"].as_u64().unwrap() > 0);
        assert_eq!(s["sample"].as_array().unwrap().len(), 12);
    }
}
