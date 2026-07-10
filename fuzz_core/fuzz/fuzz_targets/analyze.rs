#![no_main]
use libfuzzer_sys::fuzz_target;

// Response-analysis heuristics run over untrusted HTTP response bodies. They must be
// panic-free (no slice-boundary / UTF-8 / regex-index bugs) on arbitrary bytes.
fuzz_target!(|data: &[u8]| {
    let body = String::from_utf8_lossy(data);
    let _ = fuzz_core::looks_like_sqli_response(&body);
    let _ = fuzz_core::reflected_xss_indicated(&body);
});
