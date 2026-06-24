//! Contract tests — transport security engine module registry and public API stability.

use fingerprint_engine::mtls_grpc_engine::{run_mtls_grpc_result, TRANSPORT_PROBE_MODULES};

#[test]
fn module_registry_covers_full_transport_surface() {
    assert!(
        TRANSPORT_PROBE_MODULES.len() >= 38,
        "expected ≥38 live probe modules, got {}",
        TRANSPORT_PROBE_MODULES.len()
    );
    for key in [
        "tls_session_matrix",
        "weak_cipher_matrix",
        "grpc_h2c_preface",
        "must_staple_correlation",
        "tls_compression_crime",
        "dimension_scorecard",
        "coverage_manifest",
    ] {
        assert!(
            TRANSPORT_PROBE_MODULES.contains(&key),
            "missing module: {key}"
        );
    }
}

#[tokio::test]
async fn empty_target_returns_error() {
    let r = run_mtls_grpc_result("").await;
    assert_eq!(r.status, "error");
    assert!(r.summary.contains("target required"));
}
