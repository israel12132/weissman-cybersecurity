//! Classify a scan target once per job so the engine set can be *prioritized* to what's
//! actually relevant, instead of running everything in arbitrary order and having most engines
//! return `empty_ok`. Prioritization only reorders — it never prunes an engine to zero, so no
//! coverage is silently dropped.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Default)]
pub struct TargetProfile {
    pub host: String,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub ip_family: Option<IpFamily>,
    pub is_private: bool,
    /// Coarse class hints: "ip" | "hostname" | "web" | "tls" | "network".
    pub hints: Vec<&'static str>,
}

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    // [ipv6]:port
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }
    // host:port (only when a single colon — avoids splitting bare IPv6)
    if authority.matches(':').count() == 1 {
        if let Some((h, p)) = authority.split_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h, Some(port));
            }
        }
    }
    (authority, None)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

impl TargetProfile {
    pub fn classify(target: &str) -> Self {
        let t = target.trim();
        let (scheme, rest) = match t.find("://") {
            Some(i) => (Some(t[..i].to_lowercase()), &t[i + 3..]),
            None => (None, t),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let (host, port) = split_host_port(authority);
        let ip = host.parse::<IpAddr>().ok();
        let ip_family = ip.map(|a| if a.is_ipv4() { IpFamily::V4 } else { IpFamily::V6 });
        let is_private = ip.map(is_private_ip).unwrap_or(false);

        let mut hints: Vec<&'static str> = Vec::new();
        hints.push(if ip.is_some() { "ip" } else { "hostname" });
        match scheme.as_deref() {
            Some("https") => {
                hints.push("web");
                hints.push("tls");
            }
            Some("http") => hints.push("web"),
            Some("ftp") | Some("ssh") | Some("smb") | Some("rdp") => hints.push("network"),
            _ => {}
        }
        if matches!(port, Some(443 | 8443 | 9443 | 10443)) && !hints.contains(&"tls") {
            hints.push("tls");
        }
        if matches!(port, Some(80 | 443 | 8080 | 8000 | 8443)) && !hints.contains(&"web") {
            hints.push("web");
        }

        Self {
            host: host.to_string(),
            scheme,
            port,
            ip_family,
            is_private,
            hints,
        }
    }

    /// Relevance score for an engine id under this profile (higher = run earlier). Heuristic
    /// keyed on engine-id substrings + the target class; scores can be negative but the engine
    /// is still kept (reorder, don't drop).
    pub fn relevance(&self, engine_id: &str) -> i32 {
        let id = engine_id;
        let web = self.hints.contains(&"web");
        let tls = self.hints.contains(&"tls");
        let is_ip = self.hints.contains(&"ip");
        let mut score = 0;

        if web
            && (id.contains("http")
                || id.contains("web")
                || id.contains("xss")
                || id.contains("sqli")
                || id.contains("api")
                || id.contains("graphql")
                || id.contains("cache")
                || id.contains("ssrf")
                || id.contains("cors")
                || id.contains("upload"))
        {
            score += 5;
        }
        if tls && (id.contains("tls") || id.contains("ssl") || id.contains("cert") || id.contains("pqc")) {
            score += 4;
        }
        if is_ip
            && (id.contains("port")
                || id.contains("smb")
                || id.contains("netbios")
                || id.contains("network")
                || id.contains("dns")
                || id.contains("tcp")
                || id.contains("scan"))
        {
            score += 4;
        }
        // Web-app engines rarely apply to a bare IP.
        if is_ip
            && (id.contains("xss")
                || id.contains("graphql")
                || id.contains("wordpress")
                || id.contains("cms"))
        {
            score -= 2;
        }
        // IPv6-only target: deprioritize engines that assume IPv4.
        if self.ip_family == Some(IpFamily::V6) && id.contains("ipv4") {
            score -= 3;
        }
        score
    }

    /// Return the engine ids reordered by descending relevance (stable for equal scores).
    pub fn prioritize(&self, engine_ids: &[String]) -> Vec<String> {
        let mut indexed: Vec<(usize, &String)> = engine_ids.iter().enumerate().collect();
        indexed.sort_by(|(ia, a), (ib, b)| {
            self.relevance(b)
                .cmp(&self.relevance(a))
                .then(ia.cmp(ib)) // stable for equal scores
        });
        indexed.into_iter().map(|(_, s)| s.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_web_url() {
        let p = TargetProfile::classify("https://example.com/login?x=1");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.scheme.as_deref(), Some("https"));
        assert!(p.ip_family.is_none());
        assert!(p.hints.contains(&"web") && p.hints.contains(&"tls") && p.hints.contains(&"hostname"));
    }

    #[test]
    fn classifies_ipv4_with_port() {
        let p = TargetProfile::classify("10.0.0.5:445");
        assert_eq!(p.host, "10.0.0.5");
        assert_eq!(p.port, Some(445));
        assert_eq!(p.ip_family, Some(IpFamily::V4));
        assert!(p.is_private);
        assert!(p.hints.contains(&"ip"));
    }

    #[test]
    fn classifies_ipv6() {
        let p = TargetProfile::classify("[2001:db8::1]:443");
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, Some(443));
        assert_eq!(p.ip_family, Some(IpFamily::V6));
        assert!(p.hints.contains(&"tls"));
    }

    #[test]
    fn prioritizes_web_engines_for_web_target_and_keeps_all() {
        let p = TargetProfile::classify("https://example.com");
        let engines: Vec<String> = ["smb_netbios", "xss_reflected", "tls_audit", "port_scan"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ordered = p.prioritize(&engines);
        // Nothing is dropped.
        assert_eq!(ordered.len(), engines.len());
        // A web/tls engine ranks above the SMB engine for a web target.
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("xss_reflected") < pos("smb_netbios"));
        assert!(pos("tls_audit") < pos("smb_netbios"));
    }

    #[test]
    fn prioritizes_network_engines_for_bare_ip() {
        let p = TargetProfile::classify("10.0.0.5");
        let engines: Vec<String> = ["xss_reflected", "smb_netbios", "port_scan"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("smb_netbios") < pos("xss_reflected"));
        assert!(pos("port_scan") < pos("xss_reflected"));
    }
}
