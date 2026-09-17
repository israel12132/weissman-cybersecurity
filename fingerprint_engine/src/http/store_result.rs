//! Honest DB-failure mapping for HTTP handlers.
//!
//! Mirrors `serve.rs`'s `scrub_internal_error`: a DB (store) access failure is logged in full
//! server-side, but the client only ever sees a generic `503 { "error": "store_unavailable" }`
//! body — raw `sqlx::Error` text (table names, SQL, connection strings) never crosses the wire.
//! 503 (rather than 500) says "the store is transiently unavailable", which is what a failed
//! `begin_tenant_tx` / query almost always means.
//!
//! Provided for future handler slices to adopt; existing handlers are intentionally left as-is.
//! A handler adopts it by mapping its DB result through [`store_result`] and propagating with `?`:
//!
//! ```ignore
//! let row = crate::http::store_result::store_result(
//!     sqlx::query_scalar::<_, i64>("SELECT ...").fetch_one(&mut *tx).await,
//! )?;
//! ```

use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

/// What a handler returns to its caller when a store (DB) operation fails: HTTP 503 with a
/// scrubbed body carrying no internal detail.
pub type StoreUnavailable = (StatusCode, Json<Value>);

/// The scrubbed 503 response. Kept as one definition so [`store_result`] and its test agree
/// exactly on what the client sees.
#[must_use]
pub fn store_unavailable() -> StoreUnavailable {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "store_unavailable" })),
    )
}

/// Map a DB access result into something a handler can `?`-propagate.
///
/// On `Ok(v)` the value passes through untouched. On `Err(e)` the real `sqlx::Error` is logged
/// at error level server-side (mirroring `scrub_internal_error`) and the caller receives a generic
/// `503 { "error": "store_unavailable" }` — the SQL error text is never placed in the response.
pub fn store_result<T>(r: Result<T, sqlx::Error>) -> Result<T, StoreUnavailable> {
    r.map_err(|e| {
        tracing::error!(target: "http", error = %e, "store operation unavailable (db error)");
        store_unavailable()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_result_maps_db_error_to_scrubbed_503() {
        // A sqlx error whose text carries a recognizable secret token: the response must not leak it.
        let secret = "SECRET_SQL_LEAK pk=42 password=hunter2 FROM tenants";
        let err: Result<i64, sqlx::Error> = Err(sqlx::Error::Protocol(secret.to_string()));

        let (status, Json(body)) = store_result(err).expect_err("db error must map to Err");

        // 503, not 500 — signals a transient store outage.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        // Body is exactly the scrubbed marker and nothing else.
        assert_eq!(body, json!({ "error": "store_unavailable" }));
        // The raw SQL error text never appears anywhere in the serialized body.
        let serialized = body.to_string();
        assert!(
            !serialized.contains("SECRET_SQL_LEAK"),
            "response body leaked internal error text: {serialized}"
        );
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("tenants"));
    }

    #[test]
    fn store_result_passes_ok_through() {
        let ok: Result<i64, sqlx::Error> = Ok(7);
        assert_eq!(store_result(ok).ok(), Some(7));
    }
}
