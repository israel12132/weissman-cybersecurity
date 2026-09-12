//! EMA smoothing + reboot-aware uptime (category 1).

use std::sync::Mutex;
use std::sync::OnceLock;

struct Ema {
    load: Option<f64>,
    mem: Option<f64>,
    last_uptime: Option<u64>,
}

fn state() -> &'static Mutex<Ema> {
    static S: OnceLock<Mutex<Ema>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Ema {
            load: None,
            mem: None,
            last_uptime: None,
        })
    })
}

fn ema(prev: Option<f64>, value: f64, alpha: f64) -> f64 {
    match prev {
        Some(p) => alpha * value + (1.0 - alpha) * p,
        None => value,
    }
}

pub fn ema_load(value: f64) -> f64 {
    let Ok(mut g) = state().lock() else {
        return value;
    };
    let v = ema(g.load, value, 0.35);
    g.load = Some(v);
    v
}

pub fn ema_mem(value: f64) -> f64 {
    let Ok(mut g) = state().lock() else {
        return value;
    };
    let v = ema(g.mem, value, 0.35);
    g.mem = Some(v);
    v
}

/// Returns true when uptime dropped sharply (reboot). Callers still send the new
/// (small) uptime; the flag stops the server treating it as a statistical crash.
pub fn note_uptime(uptime: u64) -> bool {
    let Ok(mut g) = state().lock() else {
        return false;
    };
    let reboot = matches!(g.last_uptime, Some(prev) if prev > 120 && uptime + 60 < prev);
    g.last_uptime = Some(uptime);
    reboot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ema_moves_toward_new_value() {
        let a = ema(None, 10.0, 0.5);
        let b = ema(Some(a), 0.0, 0.5);
        assert!((b - 5.0).abs() < 0.01);
    }
}
