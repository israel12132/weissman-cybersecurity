//! UTC hour-of-week + HTTP Date / Welcome clock skew (category 4).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

static SERVER_OFFSET_MS: AtomicI64 = AtomicI64::new(0);

/// Record `Date` from an HTTP response (RFC 7231 / IMF-fixdate).
pub fn note_http_date(date_header: Option<&str>) {
    let Some(raw) = date_header else {
        return;
    };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(raw.trim()) else {
        return;
    };
    apply_server_unix_ms(parsed.timestamp_millis());
}

pub fn note_server_utc_ms(ms: i64) {
    if ms > 0 {
        apply_server_unix_ms(ms);
    }
}

fn apply_server_unix_ms(server_ms: i64) {
    let local_ms = now_ms();
    let offset = server_ms.saturating_sub(local_ms);
    SERVER_OFFSET_MS.store(offset, Ordering::Relaxed);
    if offset.abs() > 5 * 60 * 1000 {
        warn!(
            offset_ms = offset,
            "UEBA clock skew vs server exceeds 5 minutes"
        );
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn skew_secs() -> i64 {
    SERVER_OFFSET_MS.load(Ordering::Relaxed) / 1000
}

/// Monday 00:00 UTC = 0 … Sunday 23:00 UTC = 167. Always UTC so DST cannot move buckets.
pub fn hour_of_week_corrected() -> i32 {
    let corrected = now_ms().saturating_add(SERVER_OFFSET_MS.load(Ordering::Relaxed));
    let secs = (corrected / 1000).max(0);
    let days_since_epoch = secs / 86_400;
    // 1970-01-01 was Thursday. Convert to Monday=0.
    let weekday_thu0 = days_since_epoch.rem_euclid(7);
    let monday0 = (weekday_thu0 + 3) % 7;
    let hour = ((secs % 86_400) / 3600) as i32;
    (monday0 as i32 * 24 + hour).clamp(0, 167)
}

#[allow(dead_code)]
pub fn corrected_unix_secs() -> i64 {
    now_ms().saturating_add(SERVER_OFFSET_MS.load(Ordering::Relaxed)) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hour_of_week_in_range() {
        let h = hour_of_week_corrected();
        assert!((0..=167).contains(&h));
    }

    #[test]
    fn http_date_updates_skew() {
        note_http_date(Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        // 1970 is far from now — skew must be large (and clamped into i64).
        assert!(skew_secs().abs() > 60);
    }
}
