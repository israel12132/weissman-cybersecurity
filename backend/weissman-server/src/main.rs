//! Weissman enterprise HTTP server. Prefer this binary over `fingerprint_engine serve` for production.

fn main() {
    weissman_db::env_bootstrap::load_process_environment();
    let rt = fingerprint_engine::hpc_runtime::build_scan_runtime().unwrap_or_else(|e| {
        eprintln!("[Weissman] FATAL: tokio runtime: {}", e);
        std::process::exit(1);
    });
    {
        // Enter the runtime context so tracing init has an active tokio runtime: the
        // OpenTelemetry OTLP batch exporter spawns a background task at build time
        // (only when WEISSMAN_OTLP_ENDPOINT is set). Guard is scoped + dropped before
        // block_on so we never nest runtimes; the spawned task keeps running on `rt`.
        let _enter = rt.enter();
        fingerprint_engine::observability::init_tracing_from_env();
    }
    fingerprint_engine::observability::install_sovereign_panic_hook();
    if let Err(e) = rt.block_on(weissman_server::run()) {
        eprintln!("[Weissman] FATAL: {}", e);
        std::process::exit(1);
    }
}
