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
    if cmd == "adversarial_ml" {
        fingerprint_engine::adversarial_ml_engine::run_adversarial_ml(target).await;
        return;
    }
    if cmd == "autonomous_pentest" {
        fingerprint_engine::autonomous_pentest_engine::run_autonomous_pentest(target).await;
        return;
    }
    if cmd == "aws_attack" {
        fingerprint_engine::aws_attack_engine::run_aws_attack(target).await;
        return;
    }
    if cmd == "azure_attack" {
        fingerprint_engine::azure_attack_engine::run_azure_attack(target).await;
        return;
    }
    if cmd == "gcp_attack" {
        fingerprint_engine::gcp_attack_engine::run_gcp_attack(target).await;
        return;
    }
    if cmd == "iac_misconfig" {
        fingerprint_engine::iac_misconfig_engine::run_iac_misconfig(target).await;
        return;
    }
    if cmd == "k8s_container" {
        fingerprint_engine::k8s_container_engine::run_k8s_container(target).await;
        return;
    }
    if cmd == "kill_chain" {
        fingerprint_engine::kill_chain_engine::run_kill_chain(target).await;
        return;
    }
    if cmd == "llm_redteam" {
        fingerprint_engine::llm_redteam_engine::run_llm_redteam(target).await;
        return;
    }
    if cmd == "serverless_attack" {
        fingerprint_engine::serverless_attack_engine::run_serverless_attack(target).await;
        return;
    }
    if cmd == "scada_ics" {
        fingerprint_engine::scada_ics_engine::run_scada_ics(target).await;
        return;
    }
    if cmd == "iot_firmware" {
        fingerprint_engine::iot_firmware_engine::run_iot_firmware(target).await;
        return;
    }
    if cmd == "ble_rf" {
        fingerprint_engine::ble_rf_engine::run_ble_rf(target).await;
        return;
    }
    if cmd == "edr_evasion" {
        fingerprint_engine::edr_evasion_engine::run_edr_evasion(target).await;
        return;
    }
    if cmd == "waf_bypass" {
        fingerprint_engine::waf_bypass_engine::run_waf_bypass(target).await;
        return;
    }
    if cmd == "timing_sidechannel" {
        fingerprint_engine::timing_sidechannel_engine::run_timing_sidechannel(target).await;
        return;
    }
    if cmd == "antiforensics" {
        fingerprint_engine::antiforensics_engine::run_antiforensics(target).await;
        return;
    }
    if cmd == "pki_tls" {
        fingerprint_engine::pki_tls_engine::run_pki_tls(target).await;
        return;
    }
    if cmd == "password_spray" {
        fingerprint_engine::password_spray_engine::run_password_spray(target).await;
        return;
    }
    if cmd == "kerberoasting" {
        fingerprint_engine::kerberoasting_engine::run_kerberoasting(target).await;
        return;
    }
    if cmd == "saml_attack" {
        fingerprint_engine::saml_attack_engine::run_saml_attack(target).await;
        return;
    }
    if cmd == "pqc_scanner" {
        fingerprint_engine::pqc_scanner_engine::run_pqc_scanner(target).await;
        return;
    }
    if cmd == "bgp_dns_hijacking" {
        fingerprint_engine::bgp_dns_hijacking_engine::run_bgp_dns_hijacking(target).await;
        return;
    }
    if cmd == "ipv6_attack" {
        fingerprint_engine::ipv6_attack_engine::run_ipv6_attack(target).await;
        return;
    }
    if cmd == "mtls_grpc" {
        fingerprint_engine::mtls_grpc_engine::run_mtls_grpc(target).await;
        return;
    }
    if cmd == "smb_netbios" {
        fingerprint_engine::smb_netbios_engine::run_smb_netbios(target).await;
        return;
    }
    if cmd == "cicd_pipeline" {
        fingerprint_engine::cicd_pipeline_engine::run_cicd_pipeline(target).await;
        return;
    }
    if cmd == "container_registry" {
        fingerprint_engine::container_registry_engine::run_container_registry(target).await;
        return;
    }
    if cmd == "sbom_analyzer" {
        fingerprint_engine::sbom_analyzer_engine::run_sbom_analyzer(target).await;
        return;
    }
    if cmd == "typosquatting_monitor" {
        fingerprint_engine::typosquatting_monitor_engine::run_typosquatting_monitor(target).await;
        return;
    }
    if cmd == "oast_oob" {
        fingerprint_engine::oast_oob_engine::run_oast_oob(target).await;
        return;
    }
    if cmd == "deception_honeypot" {
        fingerprint_engine::deception_honeypot_engine::run_deception_honeypot(target).await;
        return;
    }
    if cmd == "digital_twin" {
        fingerprint_engine::digital_twin_engine::run_digital_twin(target).await;
        return;
    }
    if cmd == "zero_day_prediction" {
        fingerprint_engine::zero_day_prediction_engine::run_zero_day_prediction(target).await;
        return;
    }
    if cmd == "threat_emulation" {
        fingerprint_engine::threat_emulation_engine::run_threat_emulation(target).await;
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
