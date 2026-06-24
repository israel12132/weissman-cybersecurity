//! Nginx configuration analyzer — server_tokens leakage, weak TLS, directory listing, missing
//! security headers on reverse-proxy blocks.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "nginx", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const TOKENS_ON: PolicyMeta = pol!("WZ-NGX-001", "Nginx server_tokens enabled", Medium, "server_tokens on reveals exact nginx version in error pages and Server header.", "Set server_tokens off; hide version in upstream responses.", "T1592", "CWE-200", &["CIS-Nginx"], &["NIST-SI-2", "SOC2-CC7.1"]);
pub const WEAK_TLS: PolicyMeta = pol!("WZ-NGX-002", "Nginx allows deprecated TLS protocol", High, "ssl_protocols includes TLSv1, TLSv1.1 or SSLv3.", "Set ssl_protocols TLSv1.2 TLSv1.3 only.", "T1040", "CWE-326", &["CIS-Nginx"], &["NIST-SC-8", "PCI-DSS-4.1"]);
pub const AUTOINDEX: PolicyMeta = pol!("WZ-NGX-003", "Nginx autoindex enables directory listing", High, "autoindex on exposes filesystem structure and downloadable files.", "Set autoindex off; serve explicit index files only.", "T1083", "CWE-548", &["OWASP-A05"], &["NIST-AC-3", "SOC2-CC6.1"]);
pub const NO_HSTS: PolicyMeta = pol!("WZ-NGX-004", "Nginx SSL server missing HSTS header", Medium, "listen 443 ssl without add_header Strict-Transport-Security.", "Add Strict-Transport-Security with max-age >= 31536000; includeSubDomains.", "T1557", "CWE-319", &["OWASP-API8"], &["NIST-SC-8", "PCI-DSS-4.1"]);
pub const PROXY_HIDE: PolicyMeta = pol!("WZ-NGX-005", "Nginx proxy hides upstream errors (security through obscurity risk)", Medium, "proxy_intercept_errors on without custom error pages can mask upstream failures.", "Configure explicit error pages; log upstream errors; do not rely on intercept alone.", "T1082", "CWE-755", &["CIS-Nginx"], &["NIST-SI-4", "SOC2-CC7.1"]);
pub const SSL_CIPHER_WEAK: PolicyMeta = pol!("WZ-NGX-006", "Nginx SSL cipher suite includes weak algorithms", High, "ssl_ciphers includes RC4, DES, EXPORT or NULL.", "Use modern cipher suites: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:...;", "T1040", "CWE-326", &["CIS-Nginx"], &["NIST-SC-8", "PCI-DSS-4.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![TOKENS_ON, WEAK_TLS, AUTOINDEX, NO_HSTS, PROXY_HIDE, SSL_CIPHER_WEAK]
}

fn is_nginx(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("nginx.conf")
        || n.contains("sites-available/")
        || n.contains("sites-enabled/")
        || n.contains("conf.d/")
        || (n.contains("nginx/") && n.ends_with(".conf"))
        || (content.contains("server {") && content.contains("listen "))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_nginx(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("server_tokens on") || lc.contains("server_tokens\ton") {
        out.push(Finding::new(TOKENS_ON, file, file).observed("server_tokens on"));
    }
    if lc.contains("ssl_protocols") && (lc.contains("tlsv1;") || lc.contains("tlsv1.1") || lc.contains("sslv3")) {
        out.push(Finding::new(WEAK_TLS, file, file).observed("weak ssl_protocols"));
    }
    if lc.contains("autoindex on") || lc.contains("autoindex\t\ton") {
        out.push(Finding::new(AUTOINDEX, file, file).observed("autoindex on"));
    }
    if lc.contains("listen 443") && lc.contains("ssl") && !lc.contains("strict-transport-security") {
        out.push(Finding::new(NO_HSTS, file, file).observed("SSL server without HSTS"));
    }
    if lc.contains("proxy_intercept_errors on") {
        out.push(Finding::new(PROXY_HIDE, file, file).observed("proxy_intercept_errors on"));
    }
    if lc.contains("ssl_ciphers") && (lc.contains("rc4") || lc.contains("des") || lc.contains("export") || lc.contains("null")) {
        out.push(Finding::new(SSL_CIPHER_WEAK, file, file).observed("weak ssl_ciphers"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_autoindex() {
        let c = "server { listen 80; location / { autoindex on; } }";
        assert!(evaluate("nginx.conf", c).iter().any(|f| f.policy.id == AUTOINDEX.id));
    }
}
