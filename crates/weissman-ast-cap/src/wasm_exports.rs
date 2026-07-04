use js_sys::Array;
use wasm_bindgen::prelude::*;

use crate::cap_mutation_lines;

#[wasm_bindgen]
pub fn cap_ast_mutations(lines: &JsValue, max_nodes: u32, max_bytes: u32) -> Array {
    let input = Array::from(lines);
    let mut rust_lines = Vec::with_capacity(input.length() as usize);
    for i in 0..input.length() {
        if let Some(v) = input.get(i).as_string() {
            rust_lines.push(v);
        }
    }
    let refs: Vec<&str> = rust_lines.iter().map(String::as_str).collect();
    let capped = cap_mutation_lines(&refs, max_nodes as usize, max_bytes as usize);
    let out = Array::new();
    for s in capped {
        out.push(&JsValue::from_str(&s));
    }
    out
}
