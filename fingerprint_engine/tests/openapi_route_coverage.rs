//! Drift contract: the committed OpenAPI artifact (`src/openapi_paths.generated.json`) must cover
//! every route registered in `src/http/serve_route_groups.rs`. When this fails, a route was added
//! or changed without regenerating — run `node scripts/generate_openapi.mjs`.
//!
//! Pure file I/O — no database, no runtime server. Mirrors the extraction in
//! `scripts/generate_openapi.mjs` closely enough to catch missing coverage.

use std::path::Path;

/// axum `:param` -> `{param}`, `*rest` -> `{rest}` (matches the node generator).
fn to_openapi_path(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            if let Some(rest) = seg.strip_prefix(':') {
                format!("{{{rest}}}")
            } else if let Some(rest) = seg.strip_prefix('*') {
                format!("{{{rest}}}")
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Every path literal registered via `.route("<path>", ...)`, in OpenAPI `{param}` form.
/// The first double-quoted string after each `.route(` is the path (route paths carry no
/// escaped quote).
fn registered_paths(src: &str) -> Vec<String> {
    let needle = ".route(";
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = src[i..].find(needle) {
        let after = i + rel + needle.len();
        if let Some(q1rel) = src[after..].find('"') {
            let q1 = after + q1rel + 1;
            if let Some(q2rel) = src[q1..].find('"') {
                out.push(to_openapi_path(&src[q1..q1 + q2rel]));
                i = q1 + q2rel + 1;
                continue;
            }
        }
        i = after;
    }
    out
}

#[test]
fn openapi_spec_covers_every_registered_route() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let routes_src =
        std::fs::read_to_string(Path::new(manifest).join("src/http/serve_route_groups.rs"))
            .expect("read serve_route_groups.rs");
    let json_src =
        std::fs::read_to_string(Path::new(manifest).join("src/openapi_paths.generated.json"))
            .expect(
                "openapi_paths.generated.json missing — run: node scripts/generate_openapi.mjs",
            );

    let spec: serde_json::Value =
        serde_json::from_str(&json_src).expect("openapi_paths.generated.json is valid JSON");
    let paths = spec
        .get("paths")
        .and_then(|v| v.as_object())
        .expect("generated spec has a paths object");

    // Guard against an empty / truncated artifact.
    assert!(
        paths.len() >= 400,
        "generated spec has only {} paths — regenerate with node scripts/generate_openapi.mjs",
        paths.len()
    );

    // The committed artifact's recorded route count must match the live route table.
    let live_count = routes_src.matches(".route(").count();
    let recorded = spec
        .get("x-generated")
        .and_then(|g| g.get("routeCount"))
        .and_then(|v| v.as_u64())
        .expect("x-generated.routeCount present") as usize;
    assert_eq!(
        recorded, live_count,
        "openapi_paths.generated.json is stale ({recorded} routes recorded, {live_count} registered) \
         — run: node scripts/generate_openapi.mjs"
    );

    // Every registered path must be documented in the spec.
    let mut missing: Vec<String> = registered_paths(&routes_src)
        .into_iter()
        .filter(|p| !paths.contains_key(p))
        .collect();
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "routes missing from the OpenAPI spec (run node scripts/generate_openapi.mjs): {missing:?}"
    );
}
