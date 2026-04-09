//! Cryptographic policy and capability reporting: classic JWT vs PQC KEM layering.
//! Designed so RSA/ECC-heavy paths can be swapped for hybrid PQ without rewriting call sites.

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKemMode {
    /// Current production: HS256 JWT (`auth_jwt`).
    ClassicHmacJwt,
    /// Future: JWT carries PQ KEM ciphertext + classic MAC until full PQ token standards land.
    HybridMlKem768Wrapped,
}

impl SessionKemMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKemMode::ClassicHmacJwt => "classic_hs256_jwt",
            SessionKemMode::HybridMlKem768Wrapped => "hybrid_ml_kem768_wrapped",
        }
    }
}

/// Active session mechanism (env override for staged rollouts).
pub fn active_session_kem_mode() -> SessionKemMode {
    match std::env::var("WEISSMAN_SESSION_KEM_MODE")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "hybrid" | "hybrid_ml_kem768" | "pqc" => SessionKemMode::HybridMlKem768Wrapped,
        _ => SessionKemMode::ClassicHmacJwt,
    }
}

/// JSON for `/api/crypto/capabilities` and audit dashboards.
pub fn crypto_capabilities_json(ml_kem_round_trip_ok: Option<bool>) -> Value {
    let mode = active_session_kem_mode();
    json!({
        "jwt": {
            "algorithm": "HS256",
            "cookie": crate::auth_jwt::WEISSMAN_COOKIE_NAME,
            "note": "OIDC/SAML completion uses same session cookie format.",
        },
        "post_quantum": {
            "ml_kem_768_available": true,
            "ml_kem_selftest_ok": ml_kem_round_trip_ok,
            "nist_standard": "FIPS 203 (ML-KEM)",
            "session_kem_mode": mode.as_str(),
            "hybrid_rollout": "Set WEISSMAN_SESSION_KEM_MODE=hybrid when frontends accept wrapped KEM blobs.",
        },
        "fuzz_core_wasm": {
            "target": "wasm32-unknown-unknown",
            "abi_export": "fuzz_core_wasm_abi_version",
        },
    })
}
