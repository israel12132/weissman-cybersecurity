//! Recursive pipeline: shared target list, discovered paths, and wordlists for integrated scanning.
//! OSINT -> target_list; ASM -> web bases; fingerprint -> dynamic wordlist (Knowledge Base).

use std::collections::HashSet;

/// Knowledge Base: ~50 high-value endpoints per tech stack (fingerprint-based dynamic wordlist).
fn wordlist_php() -> Vec<&'static str> {
    vec![
        "/admin",
        "/admin/login",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/config.php",
        "/api.php",
        "/ajax.php",
        "/upload.php",
        "/install.php",
        "/setup.php",
        "/.env",
        "/debug",
        "/backup",
        "/sql",
        "/db",
        "/includes/config.php",
        "/vendor/autoload.php",
        "/administrator",
        "/user/login",
        "/login",
        "/register",
        "/logout",
        "/api/v1",
        "/graphql",
        "/.git/config",
        "/server-status",
        "/info.php",
        "/test.php",
        "/adminer.php",
        "/api/users",
        "/api/auth",
        "/api/config",
        "/export",
        "/import",
        "/cron.php",
        "/wp-json",
        "/xmlrpc.php",
        "/readme.html",
        "/license.txt",
        "/wp-includes/",
        "/api/admin",
        "/dashboard",
        "/manager",
        "/console",
        "/actuator",
        "/health",
    ]
}
fn wordlist_django() -> Vec<&'static str> {
    vec![
        "/admin/",
        "/admin/login/",
        "/api/",
        "/api/v1/",
        "/api/auth/",
        "/api/users/",
        "/graphql",
        "/static/",
        "/media/",
        "/__debug__/",
        "/django_admin/",
        "/accounts/login/",
        "/accounts/logout/",
        "/accounts/signup/",
        "/oauth/",
        "/api/token/",
        "/api/docs/",
        "/swagger/",
        "/redoc/",
        "/.env",
        "/config/settings",
        "/api/admin/",
        "/api/config/",
        "/health",
        "/metrics",
        "/actuator",
        "/debug",
        "/rest/",
        "/v1/",
        "/internal/",
        "/manage/",
        "/shell/",
        "/runscript/",
        "/api/feedbacks/",
        "/api/challenges/",
        "/api/basket/",
        "/api/products/",
        "/api/addresss/",
        "/api/security-questions/",
        "/ftp/",
        "/backup/",
        "/api/v2/",
        "/token/",
        "/login/",
        "/register/",
        "/logout/",
        "/dashboard/",
    ]
}
fn wordlist_spring() -> Vec<&'static str> {
    vec![
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/metrics",
        "/actuator/beans",
        "/actuator/mappings",
        "/actuator/configprops",
        "/actuator/threaddump",
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/api/users",
        "/api/admin",
        "/api/config",
        "/swagger-ui.html",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-resources",
        "/graphql",
        "/login",
        "/logout",
        "/oauth/authorize",
        "/oauth/token",
        "/manage",
        "/env",
        "/health",
        "/metrics",
        "/info",
        "/trace",
        "/dump",
        "/api/auth",
        "/api/token",
        "/rest/",
        "/rest/user/login",
        "/rest/products",
        "/admin",
        "/administrator",
        "/console",
        "/debug",
        "/.env",
        "/config",
        "/api/feedbacks",
        "/api/challenges",
        "/api/basket",
        "/api/addresss",
        "/api/security-questions",
        "/api/Users",
        "/api/Users/1",
        "/h2-console",
        "/api/v1/users",
        "/api/v1/admin",
        "/internal",
        "/actuator/logfile",
    ]
}
fn wordlist_express() -> Vec<&'static str> {
    vec![
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/users",
        "/api/auth",
        "/api/admin",
        "/rest",
        "/rest/user/login",
        "/rest/user/registration",
        "/rest/products",
        "/rest/basket/1",
        "/api/Users",
        "/api/Users/1",
        "/api/Challenges",
        "/api/Feedbacks",
        "/api/Addresss",
        "/api/SecurityQuestions",
        "/graphql",
        "/health",
        "/metrics",
        "/login",
        "/register",
        "/logout",
        "/admin",
        "/dashboard",
        "/config",
        "/.env",
        "/debug",
        "/swagger",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/upload",
        "/static",
        "/public",
        "/internal",
        "/status",
        "/version",
        "/api/config",
        "/api/token",
        "/oauth",
        "/auth/callback",
        "/session",
        "/api/v1/users",
        "/api/v1/admin",
        "/api/v1/config",
        "/ftp",
        "/backup",
        "/actuator",
        "/actuator/health",
        "/manage",
        "/console",
        "/vendor",
    ]
}

/// Dynamic wordlist from tech-stack fingerprint. Merges up to 50 endpoints per detected stack.
pub fn wordlist_for_tech_stack(tech_stack: &[String]) -> Vec<String> {
    let mut set = HashSet::new();
    for t in tech_stack {
        let t = t.to_lowercase();
        let list: Vec<&'static str> = if t.contains("php") || t.contains("wordpress") {
            wordlist_php()
        } else if t.contains("django") || t.contains("python") {
            wordlist_django()
        } else if t.contains("spring") || t.contains("java") {
            wordlist_spring()
        } else if t.contains("express")
            || t.contains("node")
            || t.contains("react")
            || t.contains("angular")
        {
            wordlist_express()
        } else {
            continue;
        };
        for p in list.into_iter().take(50) {
            set.insert(if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{}", p)
            });
        }
    }
    set.into_iter().collect()
}

/// Extract tech stack names from ASM findings (asset=fingerprint, tech_stack array).
pub fn tech_stack_from_asm_findings(findings: &[serde_json::Value]) -> Vec<String> {
    let mut out = Vec::new();
    for f in findings {
        if let Some(obj) = f.as_object() {
            if obj.get("asset").and_then(|a| a.as_str()) != Some("fingerprint") {
                continue;
            }
            if let Some(arr) = obj.get("tech_stack").and_then(|t| t.as_array()) {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

/// Expanded path wordlist when no OpenAPI/Swagger (Juice Shop, generic REST, admin, config).
/// Used by BOLA fallback, Semantic fallback, and as initial discovered_paths for path-aware engines.
pub fn expanded_path_wordlist() -> Vec<String> {
    let paths: Vec<&str> = vec![
        "",
        "/",
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v1/users",
        "/rest",
        "/rest/user/login",
        "/rest/user/registration",
        "/rest/products",
        "/rest/basket/1",
        "/api/Users",
        "/api/Users/1",
        "/api/Users/2",
        "/api/Addresss",
        "/admin",
        "/admin/login",
        "/ftp",
        "/config",
        "/config/config.json",
        "/graphql",
        "/swagger",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/login",
        "/register",
        "/health",
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/.env",
        "/debug",
        "/api/Challenges",
        "/api/Feedbacks",
        "/api/SecurityQuestions",
    ];
    paths.into_iter().map(String::from).collect()
}

/// Web ports that get their own base URL (http(s)://host:port) for scanning.
pub const WEB_PORTS: &[u16] = &[80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9443];

/// Extract subdomain strings from OSINT engine findings (value or asset_type=subdomain).
pub fn subdomains_from_osint_findings(findings: &[serde_json::Value]) -> Vec<String> {
    weissman_engines::osint::subdomains_from_osint_findings(findings)
}

/// From ASM findings, extract open ports (asset=port, value=host:port or port field).
pub fn open_ports_from_asm_findings(findings: &[serde_json::Value]) -> Vec<u16> {
    let mut ports = std::collections::HashSet::new();
    for f in findings {
        if let Some(obj) = f.as_object() {
            if obj.get("asset").and_then(|a| a.as_str()) != Some("port") {
                continue;
            }
            if let Some(p) = obj.get("port").and_then(|x| x.as_u64()) {
                if p <= u16::MAX as u64 {
                    ports.insert(p as u16);
                }
            }
            if let Some(v) = obj.get("value").and_then(|x| x.as_str()) {
                if let Some((_, port_str)) = v.rsplit_once(':') {
                    if let Ok(p) = port_str.parse::<u16>() {
                        ports.insert(p);
                    }
                }
            }
        }
    }
    ports.into_iter().collect()
}

/// Build base URLs for a host (with optional scheme) and list of ports. Only includes WEB_PORTS.
pub fn web_bases_for_host(host: &str, ports: &[u16]) -> Vec<String> {
    let host = host.trim().trim_end_matches('/');
    let host_clean = if let Some(rest) = host.strip_prefix("https://") {
        rest.split('/').next().unwrap_or(rest)
    } else if let Some(rest) = host.strip_prefix("http://") {
        rest.split('/').next().unwrap_or(rest)
    } else {
        host.split('/').next().unwrap_or(host)
    };
    let mut out = Vec::new();
    for &p in ports {
        if !WEB_PORTS.contains(&p) {
            continue;
        }
        if p == 443 {
            out.push(format!("https://{}", host_clean));
        } else if p == 80 {
            out.push(format!("http://{}", host_clean));
        } else if p == 8443 || p == 9443 {
            out.push(format!("https://{}:{}", host_clean, p));
        } else {
            out.push(format!("http://{}:{}", host_clean, p));
        }
    }
    out
}

/// Global Discovery Table: every path from any engine (Crawler, Archival, AI, ASM) is merged here.
/// 403 paths are explicitly kept for BOLA/fuzzing. No path is ignored.
#[derive(Default)]
pub struct DiscoveryContext {
    pub paths: HashSet<String>,
    pub paths_403: Vec<String>,
}

impl DiscoveryContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn merge_paths(&mut self, paths: impl IntoIterator<Item = String>) {
        for p in paths {
            let n = if p.starts_with('/') {
                p
            } else {
                format!("/{}", p)
            };
            if n.len() > 1 && n.len() < 500 {
                self.paths.insert(n);
            }
        }
    }

    pub fn merge_403(&mut self, path: String) {
        let n = if path.starts_with('/') {
            path
        } else {
            format!("/{}", path)
        };
        if !n.is_empty() && n != "/" {
            self.paths.insert(n.clone());
            self.paths_403.push(n);
        }
    }

    /// All paths as a list (including 403). Use for BOLA, Fuzz, Timing.
    pub fn all_paths(&self) -> Vec<String> {
        let mut out: Vec<String> = self.paths.iter().cloned().collect();
        for p in &self.paths_403 {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
        out
    }

    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_expanded_paths() {
        let p = expanded_path_wordlist();
        assert!(p.contains(&"/api/v1".to_string()));
        assert!(p.contains(&"/rest/user/login".to_string()));
    }
}
