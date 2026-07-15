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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_mode_as_str() {
        assert_eq!(SessionKemMode::ClassicHmacJwt.as_str(), "classic_hs256_jwt");
        assert_eq!(
            SessionKemMode::HybridMlKem768Wrapped.as_str(),
            "hybrid_ml_kem768_wrapped"
        );
    }

    #[test]
    fn kem_mode_eq_and_copy() {
        let a = SessionKemMode::ClassicHmacJwt;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(
            SessionKemMode::ClassicHmacJwt,
            SessionKemMode::HybridMlKem768Wrapped
        );
    }

    #[test]
    fn capabilities_json_stable_fields() {
        let j = crypto_capabilities_json(Some(true));
        assert_eq!(j["jwt"]["algorithm"], "HS256");
        assert_eq!(j["jwt"]["cookie"], crate::auth_jwt::WEISSMAN_COOKIE_NAME);
        assert_eq!(j["jwt"]["cookie"], "weissman_token");
        assert_eq!(
            j["post_quantum"]["ml_kem_768_available"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(j["post_quantum"]["nist_standard"], "FIPS 203 (ML-KEM)");
        assert_eq!(j["fuzz_core_wasm"]["target"], "wasm32-unknown-unknown");
        assert_eq!(
            j["fuzz_core_wasm"]["abi_export"],
            "fuzz_core_wasm_abi_version"
        );
        // session_kem_mode reflects env-driven active mode; must be one of the two known strings.
        let mode = j["post_quantum"]["session_kem_mode"]
            .as_str()
            .expect("session_kem_mode is a string");
        assert!(
            mode == "classic_hs256_jwt" || mode == "hybrid_ml_kem768_wrapped",
            "unexpected mode: {mode}"
        );
    }

    #[test]
    fn capabilities_json_selftest_flag_reflects_arg() {
        assert_eq!(
            crypto_capabilities_json(Some(true))["post_quantum"]["ml_kem_selftest_ok"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            crypto_capabilities_json(Some(false))["post_quantum"]["ml_kem_selftest_ok"],
            serde_json::Value::Bool(false)
        );
        assert!(
            crypto_capabilities_json(None)["post_quantum"]["ml_kem_selftest_ok"].is_null(),
            "None arg serializes to JSON null"
        );
    }
}
