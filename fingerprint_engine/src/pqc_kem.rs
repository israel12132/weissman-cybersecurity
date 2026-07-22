//! NIST ML-KEM (Kyber-family) smoke test for Phase 7 PQC readiness.
//! Session JWTs remain classic HS256; long-term plan is hybrid wrapping via `crypto_policy`.

use core::convert::AsRef;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand_core::OsRng;
use serde_json::{json, Value};

#[derive(Debug, Clone, serde::Serialize)]
pub struct MlKemSelfTestResult {
    pub algorithm: &'static str,
    pub ciphertext_bytes: usize,
    pub shared_secret_bytes: usize,
    pub round_trip_ok: bool,
}

/// Runs ML-KEM-768 encapsulation + decapsulation; proves the PQ stack is linked and operational.
pub fn ml_kem768_selftest() -> Result<MlKemSelfTestResult, String> {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, k_send) = ek
        .encapsulate(&mut rng)
        .map_err(|e| format!("encapsulate: {:?}", e))?;
    let k_recv = dk
        .decapsulate(&ct)
        .map_err(|e| format!("decapsulate: {:?}", e))?;
    let ct_len = AsRef::<[u8]>::as_ref(&ct).len();
    let ss_len = AsRef::<[u8]>::as_ref(&k_send).len();
    let round_trip_ok = AsRef::<[u8]>::as_ref(&k_send) == AsRef::<[u8]>::as_ref(&k_recv);
    Ok(MlKemSelfTestResult {
        algorithm: "ML-KEM-768 (FIPS 203)",
        ciphertext_bytes: ct_len,
        shared_secret_bytes: ss_len,
        round_trip_ok,
    })
}

pub fn selftest_json() -> Value {
    match ml_kem768_selftest() {
        Ok(r) => serde_json::to_value(&r).unwrap_or_else(|_| json!({ "error": "serialize" })),
        Err(e) => json!({ "error": e }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ML-KEM-768 (FIPS 203) has fixed 1088-byte ciphertexts and 32-byte shared secrets.
    // Encapsulate/decapsulate MUST agree — a deterministic property despite RNG keygen.
    #[test]
    fn selftest_round_trip_and_fixed_sizes() {
        let r = ml_kem768_selftest().expect("selftest should succeed");
        assert!(r.round_trip_ok, "encaps/decaps shared secret must match");
        assert_eq!(r.shared_secret_bytes, 32);
        assert_eq!(r.ciphertext_bytes, 1088);
        assert_eq!(r.algorithm, "ML-KEM-768 (FIPS 203)");
    }

    #[test]
    fn selftest_json_reports_success() {
        let j = selftest_json();
        assert_eq!(j["round_trip_ok"], serde_json::Value::Bool(true));
        assert_eq!(j["shared_secret_bytes"], serde_json::json!(32));
        assert_eq!(j["ciphertext_bytes"], serde_json::json!(1088));
        assert_eq!(j["algorithm"], "ML-KEM-768 (FIPS 203)");
        assert!(j.get("error").is_none(), "success path has no error key");
    }

    #[test]
    fn selftest_json_uses_snake_case_serde_fields() {
        // MlKemSelfTestResult derives Serialize with default (field-name) keys.
        let r = MlKemSelfTestResult {
            algorithm: "X",
            ciphertext_bytes: 7,
            shared_secret_bytes: 9,
            round_trip_ok: false,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["algorithm"], "X");
        assert_eq!(v["ciphertext_bytes"], serde_json::json!(7));
        assert_eq!(v["shared_secret_bytes"], serde_json::json!(9));
        assert_eq!(v["round_trip_ok"], serde_json::Value::Bool(false));
    }
}
