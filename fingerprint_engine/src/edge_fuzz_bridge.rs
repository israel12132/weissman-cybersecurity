//! Edge deployment contract: `fuzz_core` builds as WASM; workers (Cloudflare / Lambda@Edge) host it.
//! This module returns machine-readable manifests for CI and control-plane registration.

use serde_json::{json, Value};

pub const FUZZ_WASM_ABI_VERSION: u32 = 1;

/// Build + binding instructions for edge platforms (no secrets).
pub fn edge_worker_deploy_manifest() -> Value {
    json!({
        "crate": "fuzz_core",
        "rust_target": "wasm32-unknown-unknown",
        "abi_version": FUZZ_WASM_ABI_VERSION,
        "build_command": "bash scripts/build_fuzz_wasm.sh",
        "artifact": "fuzz_core/pkg/fuzz_core_bg.wasm",
        "cloudflare_workers": {
            "pattern": "Import WASM as module; call exported `fuzz_core_wasm_abi_version` for handshake.",
            "wrangler": "wasm_modules = { FUZZ_CORE = \"path/to/fuzz_core_bg.wasm\" }",
            "note": "Mutations are pure CPU; HTTP I/O stays in the Worker fetch handler.",
        },
        "aws_lambda_at_edge": {
            "pattern": "Node.js 20+ with wasm-bindgen-generated JS glue, or Rust custom runtime in regional Lambda; @Edge has stricter size limits.",
            "note": "Ship only the `cdylib` WASM + thin JS loader; keep payloads under edge size caps.",
        },
        "heartbeat_endpoint": "/api/edge-swarm/heartbeat",
        "nodes_list_endpoint": "/api/edge-swarm/nodes",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_one() {
        assert_eq!(FUZZ_WASM_ABI_VERSION, 1);
    }

    #[test]
    fn manifest_top_level_fields() {
        let m = edge_worker_deploy_manifest();
        assert_eq!(m["crate"], "fuzz_core");
        assert_eq!(m["rust_target"], "wasm32-unknown-unknown");
        assert_eq!(m["build_command"], "bash scripts/build_fuzz_wasm.sh");
        assert_eq!(m["artifact"], "fuzz_core/pkg/fuzz_core_bg.wasm");
        assert_eq!(m["heartbeat_endpoint"], "/api/edge-swarm/heartbeat");
        assert_eq!(m["nodes_list_endpoint"], "/api/edge-swarm/nodes");
    }

    #[test]
    fn manifest_abi_version_matches_constant() {
        let m = edge_worker_deploy_manifest();
        assert_eq!(m["abi_version"], FUZZ_WASM_ABI_VERSION);
        assert_eq!(m["abi_version"], 1);
    }

    #[test]
    fn manifest_has_platform_sections() {
        let m = edge_worker_deploy_manifest();
        assert!(m["cloudflare_workers"].is_object());
        assert!(m["cloudflare_workers"]["pattern"].is_string());
        assert!(m["cloudflare_workers"]["wrangler"].is_string());
        assert!(m["aws_lambda_at_edge"].is_object());
        assert!(m["aws_lambda_at_edge"]["pattern"].is_string());
    }
}
