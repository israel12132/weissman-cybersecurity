//! CLI: fingerprint, fuzz, IP scan, safe-probe, SOC engines (HTTP → `weissman-server`).
//! All SOC commands output JSON to stdout for Python: {"status":"ok"|"error","findings":[...],"message":"..."}
//!
//! **HTTP:** Use the **`weissman-server`** binary for production (rate limits, security headers, CORS).
//! The `fingerprint_engine` CLI does not expose `serve`; see workspace crate `weissman-server`.
//! Master bootstrap (optional): set `WEISSMAN_MASTER_BOOTSTRAP_EMAIL` plus `WEISSMAN_MASTER_BOOTSTRAP_PASSWORD`
//! or `WEISSMAN_MASTER_BOOTSTRAP_BCRYPT` — never commit secrets.
//! **`WEISSMAN_PUBLIC_BASE_URL`** — public origin for OIDC/SAML redirects (e.g. `https://app.example.com`).
//! SAML: `WEISSMAN_XMLSEC1_BINARY` (xmlsec1 path) for verified ACS; lab-only `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1`.
//! Optional `WEISSMAN_SAML_SP_ISSUER` (defaults to `{PUBLIC_BASE}/saml/metadata`).

use fingerprint_engine::{
    enum_subdomains, enum_subdomains_default, run_fuzzer, safe_probe,
    scan_ip_ranges_concurrent_with_port_limit, scan_targets_concurrent,
};
use std::collections::HashMap;
use std::env;
use std::path::Path;

fn main() {
    let rt = fingerprint_engine::hpc_runtime::build_scan_runtime().unwrap_or_else(|e| {
        eprintln!("[Weissman] FATAL: tokio runtime: {}", e);
        std::process::exit(1);
    });
    rt.block_on(async {
    // Load .env from current dir or project root so WEISSMAN_ADMIN_* and PORT are set
    let _ = dotenvy::dotenv();
    if let Ok(mut parent) = std::env::current_dir() {
        parent.pop();
        let env_path = parent.join(".env");
        if env_path.exists() {
            let _ = dotenvy::from_path(env_path);
        }
    }
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage:");
        eprintln!("  (HTTP)  weissman-server   # Production API + Command Center — use: cargo run -p weissman-server");
        eprintln!("  fingerprint_engine <url1> [url2 ...]");
        eprintln!("  fingerprint_engine fuzz <target_url> [base_payload]");
        eprintln!("  fingerprint_engine ips <cidr1> [cidr2 ...]");
        eprintln!("  fingerprint_engine supply_chain <target>");
        eprintln!("  fingerprint_engine osint <target>");
        eprintln!("  fingerprint_engine asm <target>");
        eprintln!("  fingerprint_engine bola_idor <target_url>");
        eprintln!("  fingerprint_engine llm_path_fuzz <target_url>");
        std::process::exit(1);
    }

    let cmd = args[0].as_str();
    let target = args.get(1).map(|s| s.as_str()).unwrap_or("");

    if cmd == "serve" {
        eprintln!(
            "[Weissman] The standalone `fingerprint_engine serve` command has been removed."
        );
        eprintln!(
            "         Use the unified production binary (global rate limit, security headers, CORS):"
        );
        eprintln!("           cargo run -p weissman-server");
        eprintln!("           nix run .#default   # default app is weissman-server");
        std::process::exit(2);
    }

    if cmd == "supply_chain" {
        fingerprint_engine::supply_chain_engine::run_supply_chain(target).await;
        return;
    }
    if cmd == "osint" {
        fingerprint_engine::osint_engine::run_osint(target).await;
        return;
    }
    if cmd == "asm" {
        fingerprint_engine::asm_engine::run_asm(target).await;
        return;
    }
    if cmd == "bola_idor" {
        fingerprint_engine::bola_idor_engine::run_bola_idor(target).await;
        return;
    }
    if cmd == "llm_path_fuzz" || cmd == "ollama_fuzz" {
        fingerprint_engine::llm_path_fuzz_engine::run_llm_path_fuzz_cli(target).await;
        return;
    }
    if cmd == "graphql_attack" {
        fingerprint_engine::graphql_attack_engine::run_graphql_attack(target).await;
        return;
    }
    if cmd == "jwt_attack" {
        fingerprint_engine::jwt_attack_engine::run_jwt_attack(target).await;
        return;
    }
    if cmd == "oauth_oidc" {
        fingerprint_engine::oauth_oidc_engine::run_oauth_oidc(target).await;
        return;
    }
    if cmd == "http_smuggling" {
        fingerprint_engine::http_smuggling_engine::run_http_smuggling(target).await;
        return;
    }
    if cmd == "prototype_pollution" {
        fingerprint_engine::prototype_pollution_engine::run_prototype_pollution(target).await;
        return;
    }
    if cmd == "ssrf_advanced" {
        fingerprint_engine::ssrf_advanced_engine::run_ssrf_advanced(target).await;
        return;
    }
    if cmd == "xxe" {
        fingerprint_engine::xxe_engine::run_xxe(target).await;
        return;
    }
    if cmd == "ssti" {
        fingerprint_engine::ssti_engine::run_ssti(target).await;
        return;
    }
    if cmd == "file_upload" {
        fingerprint_engine::file_upload_engine::run_file_upload(target).await;
        return;
    }
    if cmd == "websocket_attack" {
        fingerprint_engine::websocket_attack_engine::run_websocket_attack(target).await;
        return;
    }
    if cmd == "cache_poisoning" {
        fingerprint_engine::cache_poisoning_engine::run_cache_poisoning(target).await;
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("fuzz") {
        let _ = tracing_subscriber::fmt::try_init();
        let url = args.get(1).map(|s| s.as_str()).unwrap_or("");
        let payload = args
            .get(2)
            .map(|s| s.as_str())
            .unwrap_or(r#"{"email":"test@test.com"}"#);
        if url.is_empty() {
            eprintln!("fuzz requires target URL");
            std::process::exit(1);
        }
        run_fuzzer(url, payload).await;
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("ips") {
        let rest: Vec<String> = args.into_iter().skip(1).collect();
        let deep = rest.iter().any(|s| s == "--deep")
            || std::env::var("WEISSMAN_DEEP_SCAN")
                .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
        let cidrs: Vec<String> = rest
            .into_iter()
            .filter(|s| s != "--deep" && !s.trim().is_empty())
            .collect();
        if cidrs.is_empty() {
            eprintln!(
                "ips requires at least one CIDR (e.g. 10.0.0.0/24). Use --deep for Top 1000 ports."
            );
            std::process::exit(1);
        }
        let port_limit = if deep { 1000_usize } else { 3 };
        let results: HashMap<String, Vec<String>> =
            scan_ip_ranges_concurrent_with_port_limit(&cidrs, port_limit).await;
        match serde_json::to_string(&results) {
            Ok(s) => println!("{}", s),
            Err(_) => println!("{}", serde_json::json!({})),
        }
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("subdomains") {
        let domain = args.get(1).map(|s| s.as_str()).unwrap_or("").to_string();
        let mut wordlist: Vec<String> = fingerprint_engine::DEFAULT_SUBDOMAINS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut i = 2;
        while i < args.len() {
            if args.get(i).map(|s| s.as_str()) == Some("--wordlist") && i + 1 < args.len() {
                if let Ok(contents) = std::fs::read_to_string(Path::new(&args[i + 1])) {
                    wordlist = contents
                        .lines()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                i += 2;
                continue;
            }
            i += 1;
        }
        if domain.is_empty() {
            eprintln!("subdomains requires <domain>");
            std::process::exit(1);
        }
        let found = if wordlist.is_empty() {
            enum_subdomains_default(&domain).await
        } else {
            enum_subdomains(&domain, &wordlist, 200).await
        };
        match serde_json::to_string(&found) {
            Ok(s) => println!("{}", s),
            Err(_) => println!("[]"),
        }
        return;
    }

    if args.first().map(|s| s.as_str()) == Some("safe-probe") {
        let url = args.get(1).map(|s| s.as_str()).unwrap_or("");
        let tech_hint = args.get(2).map(|s| s.as_str()).unwrap_or("");
        if url.is_empty() {
            eprintln!("safe-probe requires <url> [tech_hint]");
            std::process::exit(1);
        }
        if let Some(result) = safe_probe(url, tech_hint).await {
            if let Ok(s) = serde_json::to_string(&result) {
                println!("{}", s);
            }
        } else {
            println!("{}", serde_json::json!({"error": "probe_failed"}));
        }
        return;
    }

    let urls: Vec<String> = args.into_iter().filter(|s| !s.trim().is_empty()).collect();
    let results: HashMap<String, Vec<String>> = scan_targets_concurrent(&urls).await;

    match serde_json::to_string(&results) {
        Ok(s) => println!("{}", s),
        Err(_) => println!("{}", serde_json::json!({})),
    }
    });
}
