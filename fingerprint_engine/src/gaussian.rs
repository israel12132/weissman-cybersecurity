//! Box–Muller Gaussian sampling (no extra crate; matches `rand_distr::Normal`).

use rand::RngExt;

/// Sample N(mean, std) via polar Box–Muller. `std` is clamped to a tiny epsilon.
#[must_use]
pub fn sample_normal(mean: f64, std: f64) -> f64 {
    let std = if std.is_finite() && std > 1e-9 {
        std
    } else {
        1e-9
    };
    let mut rng = rand::rng();
    loop {
        let u: f64 = rng.random_range(-1.0..1.0);
        let v: f64 = rng.random_range(-1.0..1.0);
        let s = u * u + v * v;
        if s > 0.0 && s < 1.0 {
            let z: f64 = (-2.0_f64 * s.ln() / s).sqrt();
            return mean + std * u * z;
        }
    }
}

/// Deterministic N(mean, std) from a 64-bit seed (stable per attacker/decoy edge).
#[must_use]
pub fn sample_normal_seeded(mean: f64, std: f64, seed: u64) -> f64 {
    let std = if std.is_finite() && std > 1e-9 {
        std
    } else {
        1e-9
    };
    let mut s = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    loop {
        let u = splitmix_unit(&mut s) * 2.0 - 1.0;
        let v = splitmix_unit(&mut s) * 2.0 - 1.0;
        let r = u * u + v * v;
        if r > 0.0 && r < 1.0 {
            let z: f64 = (-2.0_f64 * r.ln() / r).sqrt();
            return mean + std * u * z;
        }
    }
}

fn splitmix_unit(state: &mut u64) -> f64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z >> 11) as f64 / ((1u64 << 53) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_is_deterministic() {
        let a = sample_normal_seeded(5.0, 1.5, 42);
        let b = sample_normal_seeded(5.0, 1.5, 42);
        assert!((a - b).abs() < 1e-12);
        let c = sample_normal_seeded(5.0, 1.5, 43);
        assert!((a - c).abs() > 1e-9);
    }

    #[test]
    fn random_samples_cluster_near_mean() {
        let mut sum = 0.0;
        for _ in 0..800 {
            sum += sample_normal(8.5, 2.1);
        }
        let mean = sum / 800.0;
        assert!(
            (mean - 8.5).abs() < 0.5,
            "empirical mean {mean} drifted from 8.5"
        );
    }
}
