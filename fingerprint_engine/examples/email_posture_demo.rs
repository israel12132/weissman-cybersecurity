//! Temporary end-to-end live demo of the email_dns_posture engine (deleted after verification).
use fingerprint_engine::email_dns_posture_engine::run_email_dns_posture_result;
use fingerprint_engine::engine_dispatch::EngineRunContext;

#[tokio::main]
async fn main() {
    // SMTP probing is slow/blocked in many sandboxes; turn it off for a fast DNS+HTTPS demo.
    let mut ctx = EngineRunContext::default();
    ctx.job_params = serde_json::json!({ "check_smtp_tls": "false", "check_dane": "false" });

    for target in [
        "https://paypal.com",
        "https://github.com",
        "https://example.com",
    ] {
        let r = run_email_dns_posture_result(target, &ctx).await;
        println!("\n================ {target} ================");
        println!("status={} | {}", r.status, r.message);
        if let Some(s) = r.findings.first() {
            let g = s.get("grade").and_then(|v| v.as_str()).unwrap_or("?");
            let score = s.get("score").and_then(|v| v.as_i64()).unwrap_or(-1);
            let spoof = s
                .get("spoofability")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let sub = s.get("subscores").cloned().unwrap_or_default();
            let provider = s.get("provider").and_then(|v| v.as_str()).unwrap_or("n/a");
            println!("GRADE {g} ({score}/100) | spoofability={spoof} | provider={provider}");
            println!("subscores={sub}");
            if let Some(reason) = s.get("spoofability_reason").and_then(|v| v.as_str()) {
                println!("reason: {reason}");
            }
            if let Some(rm) = s.get("roadmap").and_then(|v| v.as_array()) {
                println!("roadmap (top {}):", rm.len().min(3));
                for step in rm.iter().take(3) {
                    println!("  - {}", step.as_str().unwrap_or(""));
                }
            }
        }
        // A couple of representative non-summary findings.
        for f in r.findings.iter().skip(1).take(3) {
            let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("?");
            let title = f.get("title").and_then(|v| v.as_str()).unwrap_or("?");
            println!("  [{sev}] {title}");
        }
    }
}
