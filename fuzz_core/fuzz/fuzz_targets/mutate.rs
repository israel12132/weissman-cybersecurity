#![no_main]
use libfuzzer_sys::fuzz_target;

// The mutation + URL-building surface takes attacker-influenced strings (payload bases,
// target URLs). It must never panic or hang on arbitrary input. Counts are bounded so a
// fuzz input can't drive an allocation blow-up.
fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = fuzz_core::smart_payload_mutations(&s);

    let m = fuzz_core::Mutator::new(s.to_string());
    let _ = m.mutations();
    let _ = m.smart_mutations();
    let _ = m.bit_flip();
    let _ = m.byte_swap();

    let _ = fuzz_core::build_param_injection_probe_urls(&s, 16);
    let _ = fuzz_core::append_query_param(&s, "q", &s);
});
