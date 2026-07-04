//! OpenAPI / Swagger static analyzer — detects API surface misconfigurations that become
//! initial-access and data-exfiltration vectors (unauthenticated admin paths, cleartext servers,
//! wildcard CORS, credentials-in-query). Fully deterministic JSON/YAML parsing; no live probing.

use super::model::{Finding, PolicyMeta, Severity};
use serde_json::Value;

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "openapi",
            provider: "generic",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const NO_SECURITY: PolicyMeta = pol!("WZ-OAS-001", "OpenAPI spec defines no security schemes", High, "The API specification has no securitySchemes/securityDefinitions, encouraging unauthenticated implementations.", "Define securitySchemes (OAuth2, API key header, mutual TLS) and apply security to all non-public operations.", "T1190", "CWE-306", &["OWASP-API2", "OWASP-API8"], &["NIST-AC-3", "PCI-DSS-6.5.10", "SOC2-CC6.1"]);
pub const HTTP_SERVER: PolicyMeta = pol!(
    "WZ-OAS-002",
    "OpenAPI server URL uses cleartext HTTP",
    High,
    "A server entry uses http://, exposing tokens and PII to on-path interception.",
    "Use https:// only; enforce TLS 1.2+ and HSTS at the gateway.",
    "T1040",
    "CWE-319",
    &["OWASP-API8"],
    &["NIST-SC-8", "PCI-DSS-4.1", "HIPAA-164.312(e)(1)"]
);
pub const WILDCARD_CORS: PolicyMeta = pol!("WZ-OAS-003", "OpenAPI enables wildcard CORS origin", Medium, "Access-Control-Allow-Origin: * permits any website to call the API from a victim's browser session.", "Restrict CORS to known front-end origins; never use * with credentials.", "T1185", "CWE-942", &["OWASP-API8"], &["NIST-SC-7", "SOC2-CC6.6"]);
pub const SENSITIVE_UNAUTH: PolicyMeta = pol!("WZ-OAS-004", "Sensitive API path lacks security requirement", Critical, "An admin/debug/actuator/internal path is defined without a security requirement on the operation.", "Require authentication and authorization on every sensitive operation; remove debug endpoints from production specs.", "T1190", "CWE-306", &["OWASP-API2", "OWASP-API5"], &["NIST-AC-3", "PCI-DSS-6.5.10", "MITRE-T1190"]);
pub const KEY_IN_QUERY: PolicyMeta = pol!("WZ-OAS-005", "API key transmitted in query parameter", High, "An apiKey security scheme uses query parameter location, leaking keys via logs, referrers and browser history.", "Move API keys to Authorization header or mTLS.", "T1552", "CWE-598", &["OWASP-API2"], &["NIST-IA-5", "PCI-DSS-8.2.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        NO_SECURITY,
        HTTP_SERVER,
        WILDCARD_CORS,
        SENSITIVE_UNAUTH,
        KEY_IN_QUERY,
    ]
}

fn parse_doc(content: &str) -> Option<Value> {
    if content.trim_start().starts_with('{') {
        serde_json::from_str(content).ok()
    } else {
        serde_yaml::from_str(content).ok()
    }
}

fn is_sensitive_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "admin", "debug", "actuator", "internal", "manage", "console", "swagger", "graphql",
        "backup", "export",
    ]
    .iter()
    .any(|k| p.contains(k))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(doc) = parse_doc(content) else {
        return out;
    };

    let is_swagger2 = doc.get("swagger").is_some();
    let is_oas3 = doc.get("openapi").is_some();
    if !is_swagger2 && !is_oas3 {
        return out;
    }

    // ── servers / schemes ──
    if let Some(servers) = doc.get("servers").and_then(Value::as_array) {
        for srv in servers {
            if let Some(url) = srv.get("url").and_then(Value::as_str) {
                if url.to_ascii_lowercase().starts_with("http://") {
                    out.push(
                        Finding::new(HTTP_SERVER, url, file)
                            .observed(format!("servers.url = {url}")),
                    );
                }
            }
        }
    }
    if let Some(host) = doc.get("host").and_then(Value::as_str) {
        let schemes = doc.get("schemes").and_then(Value::as_array);
        let only_http = schemes
            .map(|s| s.iter().all(|x| x.as_str() == Some("http")))
            .unwrap_or(true);
        if only_http && !host.is_empty() {
            out.push(
                Finding::new(HTTP_SERVER, host, file)
                    .observed("swagger host with http-only schemes"),
            );
        }
    }

    // ── security schemes ──
    let has_schemes = doc
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(Value::as_object)
        .map(|m| !m.is_empty())
        .unwrap_or(false)
        || doc
            .get("securityDefinitions")
            .and_then(Value::as_object)
            .map(|m| !m.is_empty())
            .unwrap_or(false);

    if !has_schemes {
        out.push(
            Finding::new(NO_SECURITY, file, file)
                .observed("no securitySchemes/securityDefinitions"),
        );
    }

    // apiKey in query
    if let Some(schemes) = doc
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .or_else(|| doc.get("securityDefinitions"))
    {
        if let Some(obj) = schemes.as_object() {
            for (name, sch) in obj {
                let loc = sch
                    .get("in")
                    .or_else(|| sch.get("in"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let typ = sch.get("type").and_then(Value::as_str).unwrap_or("");
                if typ == "apiKey" && loc == "query" {
                    out.push(
                        Finding::new(KEY_IN_QUERY, name, file)
                            .observed(format!("{name}: apiKey in query")),
                    );
                }
            }
        }
    }

    // wildcard CORS in x-* extensions or responses
    let lc = content.to_ascii_lowercase();
    if lc.contains("access-control-allow-origin") && (lc.contains("'*'") || lc.contains("\"*\"")) {
        out.push(
            Finding::new(WILDCARD_CORS, file, file).observed("Access-Control-Allow-Origin: *"),
        );
    }

    // ── paths without security on sensitive routes ──
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (path, ops) in paths {
            if !is_sensitive_path(path) {
                continue;
            }
            if let Some(op_map) = ops.as_object() {
                for (method, op) in op_map {
                    if matches!(
                        method.as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
                    ) {
                        let op_sec = op.get("security");
                        let global_sec = doc.get("security");
                        let secured = op_sec
                            .map(|s| !s.as_array().map(|a| a.is_empty()).unwrap_or(true))
                            .unwrap_or(false)
                            || global_sec
                                .map(|s| !s.as_array().map(|a| a.is_empty()).unwrap_or(true))
                                .unwrap_or(false);
                        if !secured && !has_schemes {
                            out.push(
                                Finding::new(SENSITIVE_UNAUTH, &format!("{method} {path}"), file)
                                    .observed(format!(
                                        "{method} {path} — no security on sensitive route"
                                    )),
                            );
                        } else if !secured {
                            out.push(
                                Finding::new(SENSITIVE_UNAUTH, &format!("{method} {path}"), file)
                                    .observed(format!("{method} {path} — operation.security absent on sensitive route")),
                            );
                        }
                    }
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_http_and_sensitive_path() {
        let spec = r#"{
          "openapi": "3.0.0",
          "servers": [{"url": "http://api.example.com"}],
          "paths": {
            "/admin/users": { "get": { "responses": { "200": { "description": "ok" } } } }
          }
        }"#;
        let f = evaluate("openapi.json", spec);
        assert!(f.iter().any(|x| x.policy.id == HTTP_SERVER.id));
        assert!(f.iter().any(|x| x.policy.id == SENSITIVE_UNAUTH.id));
        assert!(f.iter().any(|x| x.policy.id == NO_SECURITY.id));
    }
}
