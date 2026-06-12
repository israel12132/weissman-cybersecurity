//! Reproducible PoC strings (`poc_exploit`) and npm/OSV search prefix from client targets.

use serde_json::{Map, Value};

/// Prefix derived from a client target URL or hostname (npm search `text=` parameter for supply-chain PoCs).
#[must_use]
pub fn client_target_search_prefix(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        return String::new();
    }
    if let Some(rest) = target.strip_prefix("http://") {
        if let Some(host) = rest.split('/').next() {
            if host.contains('.') {
                return host.split('.').next().unwrap_or(host).to_string();
            }
            return host.to_string();
        }
    }
    if let Some(rest) = target.strip_prefix("https://") {
        if let Some(host) = rest.split('/').next() {
            if host.contains('.') {
                return host.split('.').next().unwrap_or(host).to_string();
            }
            return host.to_string();
        }
    }
    if target.contains('.') {
        return target.split('.').next().unwrap_or(target).to_string();
    }
    target[..target.len().min(32)].to_string()
}

/// Raw reproducible command for `poc_exploit`: prefer engine output, then infer from URL/method/body.
#[must_use]
pub fn infer_poc_exploit(obj: &Map<String, Value>, client_target: &str) -> String {
    if let Some(p) = obj.get("poc_exploit").and_then(Value::as_str) {
        if !p.trim().is_empty() {
            return p.to_string();
        }
    }
    if let Some(c) = obj.get("curl_command").and_then(Value::as_str) {
        if !c.trim().is_empty() {
            return c.to_string();
        }
    }
    let mut url = obj
        .get("url")
        .or_else(|| obj.get("target_url"))
        .or_else(|| obj.get("target"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if url.is_empty() {
        let path_only = obj.get("path").and_then(Value::as_str).unwrap_or("").trim();
        if !path_only.is_empty() && !client_target.trim().is_empty() {
            let base = client_target.trim().trim_end_matches('/');
            let p = if path_only.starts_with('/') {
                path_only.to_string()
            } else {
                format!("/{}", path_only)
            };
            url = format!("{}{}", base, p);
        }
    }
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_uppercase();
    let mut body = String::new();
    if let Some(b) = obj.get("body") {
        if let Some(s) = b.as_str() {
            body = s.to_string();
        } else if b.is_object() || b.is_array() {
            body = serde_json::to_string(b).unwrap_or_default();
        }
    }
    if body.is_empty() {
        if let Some(s) = obj.get("request_body").and_then(Value::as_str) {
            body = s.to_string();
        } else if let Some(s) = obj.get("payload_preview").and_then(Value::as_str) {
            body = s.to_string();
        }
    }
    if !url.is_empty() {
        let u = url.as_str().trim();
        if method == "GET" || body.is_empty() {
            return format!("curl -sS -k -X {} '{}'", method, u.replace('\'', "'\\''"));
        }
        let b_esc = body.replace('\\', "\\\\").replace('\'', "'\\''");
        return format!(
            "curl -sS -k -X {} '{}' -H 'Content-Type: application/json' -d '{}'",
            method,
            u.replace('\'', "'\\''"),
            b_esc
        );
    }
    if obj.get("type").and_then(Value::as_str) == Some("supply_chain") {
        let pkg = obj.get("package").and_then(Value::as_str).unwrap_or("");
        let eco_label = obj
            .get("ecosystem")
            .and_then(Value::as_str)
            .unwrap_or("npm");
        // Map the UI ecosystem label to the exact OSV ecosystem identifier.
        let osv_eco = match eco_label {
            "pypi" => "PyPI",
            "cargo" => "crates.io",
            "go" => "Go",
            "maven" => "Maven",
            "rubygems" => "RubyGems",
            "composer" => "Packagist",
            _ => "npm",
        };
        let version = obj.get("version").and_then(Value::as_str).unwrap_or("");
        // Version-anchored OSV query: OSV performs the affected-range match, so a
        // result proves *this exact version* is affected (no name-only guessing).
        let osv_json = if version.is_empty() {
            serde_json::json!({ "package": { "name": pkg, "ecosystem": osv_eco } })
        } else {
            serde_json::json!({ "version": version, "package": { "name": pkg, "ecosystem": osv_eco } })
        };
        let osv_esc = serde_json::to_string(&osv_json)
            .unwrap_or_default()
            .replace('\'', "'\\''");
        // Prefer the on-target evidence URL (manifest/SBOM/bundle) that proves presence.
        let evidence = obj
            .get("evidence_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !evidence.is_empty() {
            let ev = evidence.replace('\'', "'\\''");
            return format!(
                "# 1) Evidence the component is present on the target:\n\
                 curl -sS '{}'\n\
                 # 2) Confirm the advisory applies to the observed version (OSV range-matches):\n\
                 curl -sS -X POST 'https://api.osv.dev/v1/query' -H 'Content-Type: application/json' -d '{}'",
                ev, osv_esc
            );
        }
        return format!(
            "# Confirm the advisory applies to the observed version (OSV range-matches):\n\
             curl -sS -X POST 'https://api.osv.dev/v1/query' -H 'Content-Type: application/json' -d '{}'",
            osv_esc
        );
    }
    String::new()
}
