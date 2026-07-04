//! Capability-based Engine UI manifest protocol — single source of truth for morphing C2 chrome.
//!
//! Manifests are loaded from `shared/engine_ui_manifests.json` at compile time and served via
//! `GET /api/engines/ui-manifests` with cryptographic provenance (HMAC-SHA256).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

const MANIFESTS_JSON: &str = include_str!("../../shared/engine_ui_manifests.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUiCapabilities {
    #[serde(default)]
    pub requires_target_input: bool,
    #[serde(default)]
    pub requires_ast_viewer: bool,
    #[serde(default)]
    pub requires_template_runner: bool,
    #[serde(default)]
    pub needs_memory_telemetry: bool,
    #[serde(default)]
    pub needs_live_telemetry: bool,
    #[serde(default)]
    pub requires_kill_switch: bool,
    #[serde(default)]
    pub requires_agent_gate: bool,
    #[serde(default)]
    pub requires_scan_dispatch: bool,
    #[serde(default)]
    pub requires_payload_tuning: bool,
    #[serde(default)]
    pub max_ast_nodes: u32,
}

impl Default for EngineUiCapabilities {
    fn default() -> Self {
        Self {
            requires_target_input: false,
            requires_ast_viewer: false,
            requires_template_runner: false,
            needs_memory_telemetry: false,
            needs_live_telemetry: false,
            requires_kill_switch: false,
            requires_agent_gate: false,
            requires_scan_dispatch: false,
            requires_payload_tuning: false,
            max_ast_nodes: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUiChrome {
    #[serde(default = "default_badge_color")]
    pub badge_color: String,
}

impl Default for EngineUiChrome {
    fn default() -> Self {
        Self {
            badge_color: default_badge_color(),
        }
    }
}

fn default_badge_color() -> String {
    "#22d3ee".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineUiManifest {
    pub engine_id: String,
    pub route_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_i18n_key: Option<String>,
    #[serde(default)]
    pub capabilities: EngineUiCapabilities,
    #[serde(default)]
    pub chrome: EngineUiChrome,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    version: u32,
    manifests: Vec<EngineUiManifest>,
}

fn load_file() -> ManifestFile {
    serde_json::from_str(MANIFESTS_JSON).unwrap_or(ManifestFile {
        version: 1,
        manifests: vec![],
    })
}

/// All registered UI manifests (compile-time embedded, runtime-served).
pub fn all_manifests() -> Vec<EngineUiManifest> {
    load_file().manifests
}

fn route_index(manifests: &[EngineUiManifest]) -> HashMap<String, EngineUiManifest> {
    let mut map = HashMap::new();
    for m in manifests {
        for path in &m.route_paths {
            let p = normalize_route(path);
            map.insert(p, m.clone());
        }
    }
    map
}

fn normalize_route(path: &str) -> String {
    let mut p = path.trim().to_string();
    if !p.starts_with('/') {
        p.insert(0, '/');
    }
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

/// Resolve manifest by basename-relative route (e.g. `/ast-fuzzing`).
#[must_use]
pub fn resolve_by_route(pathname: &str) -> Option<EngineUiManifest> {
    let mut p = pathname.trim();
    if p.starts_with("/command-center") {
        p = p.strip_prefix("/command-center").unwrap_or(p);
    }
    let p = normalize_route(if p.is_empty() { "/" } else { p });
    let idx = route_index(&all_manifests());
    if let Some(m) = idx.get(&p) {
        return Some(m.clone());
    }
    // Parametric profile routes: /engines/top-tier/:id, /engines/business/:id, /engines/:id
    const PREFIX_RULES: [(&str, bool); 5] = [
        ("/engines/top-tier/", true),
        ("/engines/business/", true),
        ("/engines/", false),
        ("/digital-twin/", false),
        ("/timing-profiler/", false),
    ];
    for (prefix, take_last) in PREFIX_RULES {
        if let Some(rest) = p.strip_prefix(prefix) {
            if rest.is_empty() {
                continue;
            }
            let engine_id = if take_last {
                rest.split('/').filter(|s| !s.is_empty()).next_back()
            } else if prefix == "/digital-twin/" {
                Some("digital_twin")
            } else if prefix == "/timing-profiler/" {
                Some("side_channel")
            } else {
                rest.split('/').next()
            };
            if let Some(id) = engine_id.filter(|s| !s.is_empty()) {
                return resolve_by_engine_id(id);
            }
        }
    }
    None
}

/// Resolve manifest by canonical engine id.
#[must_use]
pub fn resolve_by_engine_id(engine_id: &str) -> Option<EngineUiManifest> {
    let id = engine_id.trim();
    all_manifests()
        .into_iter()
        .find(|m| m.engine_id == id)
        .or_else(|| {
            // Synthetic manifest for dynamic engine profile routes.
            Some(EngineUiManifest {
                engine_id: id.to_string(),
                route_paths: vec![format!("/engines/{id}")],
                evidence_i18n_key: Some("pages.engineDetail.evidence_notice".into()),
                capabilities: EngineUiCapabilities {
                    requires_target_input: true,
                    requires_scan_dispatch: true,
                    requires_agent_gate: true,
                    requires_kill_switch: true,
                    needs_live_telemetry: true,
                    ..Default::default()
                },
                chrome: EngineUiChrome {
                    badge_color: "#22d3ee".into(),
                },
            })
        })
}

/// JSON for `GET /api/engines/ui-manifests` with provenance envelope.
pub fn to_json() -> Value {
    let manifests = all_manifests();
    let mut body = json!({
        "version": load_file().version,
        "total": manifests.len(),
        "manifests": manifests,
    });
    if let Some(secret) = crate::engine_capabilities::provenance_signing_secret() {
        if let Some(prov) = weissman_ui_provenance::sign_capabilities_manifest(&body, &secret) {
            body["provenance"] = serde_json::to_value(prov).unwrap_or(Value::Null);
        }
    }
    body
}

/// JSON for `GET /api/engines/ui-manifests/by-route`.
pub fn to_json_by_route(pathname: &str) -> Value {
    match resolve_by_route(pathname) {
        Some(m) => json!({ "ok": true, "manifest": m }),
        None => json!({ "ok": false, "detail": "no manifest for route" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tooling_hubs_have_specialized_capabilities() {
        let ast = resolve_by_route("/ast-fuzzing").expect("ast manifest");
        assert!(ast.capabilities.requires_ast_viewer);
        assert!(ast.capabilities.requires_kill_switch);
        let tpl = resolve_by_route("/template-engine").expect("template manifest");
        assert!(tpl.capabilities.requires_template_runner);
        assert_eq!(tpl.engine_id, "template_engine");
    }

    #[test]
    fn jwt_lab_resolves() {
        let m = resolve_by_route("/jwt-lab").expect("jwt");
        assert_eq!(m.engine_id, "jwt_attack");
    }
}
