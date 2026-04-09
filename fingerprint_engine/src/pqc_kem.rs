//! NIST ML-KEM (Kyber-family) smoke test for Phase 7 PQC readiness.
//! Session JWTs remain classic HS256; long-term plan is hybrid wrapping via `crypto_policy`.

use core::convert::AsRef;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use rand::rngs::OsRng;
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
