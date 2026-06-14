//! Live detection benchmark: runs REAL engines (and the new PoC sandbox verifier) against
//! deterministic local fixtures with known ground truth, then asserts a perfect repro/FP score on
//! this controlled corpus. This is the seed of a measurable "world-class detection" claim — extend
//! the fixture corpus and the thresholds become a real CI quality gate.
//!
//! No engine internals are mocked: an in-process axum server serves a deliberately-vulnerable app
//! and a benign app; the engines issue real HTTP against them.

use axum::extract::RawQuery;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;
use std::time::Duration;

use fingerprint_engine::advanced_web_engines::run_graphql_deep_attack_result;
use fingerprint_engine::attack_chain_planner::plan_from_findings;
use fingerprint_engine::benchmark::{BenchOutcome, BenchReport};
use fingerprint_engine::correlation_rules::{default_rules, evaluate_all, events_from_findings};
use fingerprint_engine::itdr::{analyze as itdr_analyze, AuthEvent, ItdrConfig};
use fingerprint_engine::poc_sandbox::verify_poc;
use fingerprint_engine::sigma_rules::{
    evaluate as sigma_evaluate, FieldMatch, Op, Selection, SigmaRule,
};
use fingerprint_engine::template_probe::{builtin_templates, HttpResponseView};

async fn graphql_introspection_open() -> impl IntoResponse {
    // A vulnerable GraphQL endpoint with introspection enabled.
    Json(serde_json::json!({
        "data": {
            "__schema": {
                "types": [{"name": "Query"}, {"name": "User"}],
                "mutationType": {"name": "Mutation"}
            }
        }
    }))
}

async fn reflect_query(RawQuery(q): RawQuery) -> String {
    // A trivially-injectable endpoint that reflects the raw query string back into the body, so a
    // PoC whose payload carries a unique proof marker is observably reflected.
    format!("reflected query: {}", q.unwrap_or_default())
}

async fn benign() -> &'static str {
    "benign static response — nothing reflected, no schema"
}

fn vulnerable_app() -> Router {
    Router::new()
        .route("/graphql", post(graphql_introspection_open))
        .route("/echo", get(reflect_query))
}

fn benign_app() -> Router {
    Router::new().fallback(benign)
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    // brief readiness yield
    tokio::time::sleep(Duration::from_millis(80)).await;
    addr
}

#[tokio::test]
async fn benchmark_repro_and_fp_against_fixtures() {
    // The fixtures are loopback; allow private scan targets for the sandbox scope guard.
    std::env::set_var("WEISSMAN_ALLOW_PRIVATE_SCAN_TARGETS", "1");

    let vuln = spawn(vulnerable_app()).await;
    let safe = spawn(benign_app()).await;
    let client = reqwest::Client::new();
    let mut report = BenchReport::new();

    // ── Case 1: GraphQL introspection on the vulnerable app (expect a real detection) ──
    let g_vuln = run_graphql_deep_attack_result(&format!("http://{vuln}")).await;
    let g_vuln_detected = g_vuln.findings.iter().any(|f| {
        f.get("severity")
            .and_then(|s| s.as_str())
            .map(|s| s != "info")
            .unwrap_or(false)
    });
    report.push(BenchOutcome::new(
        "graphql_introspection::vulnerable",
        "graphql_deep_attack",
        true,
        g_vuln_detected,
        g_vuln.findings.len(),
        g_vuln.message.clone(),
    ));

    // ── Case 2: GraphQL probe on the benign app (expect no detection) ──
    let g_safe = run_graphql_deep_attack_result(&format!("http://{safe}")).await;
    report.push(BenchOutcome::new(
        "graphql_introspection::benign",
        "graphql_deep_attack",
        false,
        !g_safe.findings.is_empty(),
        g_safe.findings.len(),
        g_safe.message.clone(),
    ));

    // ── Case 3: Sandbox-verified exploitation, marker reflected (expect VERIFIED) ──
    let marker = "WEISSMAN_PROOF_7F3A1C";
    let v_vuln = verify_poc(
        &format!("http://{vuln}/echo"),
        "GET",
        marker,
        marker,
        None,
        &client,
    )
    .await;
    report.push(BenchOutcome::new(
        "poc_sandbox::reflected",
        "poc_sandbox",
        true,
        v_vuln.verified,
        v_vuln.verified as usize,
        format!(
            "executor={} signal={} sha256={}",
            v_vuln.executor, v_vuln.signal, v_vuln.evidence_sha256
        ),
    ));

    // ── Case 4: Sandbox verification on the benign app (expect NOT verified) ──
    let v_safe = verify_poc(
        &format!("http://{safe}/echo"),
        "GET",
        marker,
        marker,
        None,
        &client,
    )
    .await;
    report.push(BenchOutcome::new(
        "poc_sandbox::benign",
        "poc_sandbox",
        false,
        v_safe.verified,
        v_safe.verified as usize,
        format!("executor={} signal={}", v_safe.executor, v_safe.signal),
    ));

    // ── Case 5: Autonomous attack-chain planner reaches the objective from a verified RCE ──
    let strong_findings = vec![serde_json::json!({
        "type": "poe_synthesis",
        "title": "Weaponized vulnerability — TRUE PoE verified",
        "severity": "critical",
        "verified": true,
        "mitre_attack": "T1190"
    })];
    let chain = plan_from_findings(&strong_findings, "impact:objective");
    report.push(BenchOutcome::new(
        "attack_chain_planner::reaches_objective",
        "attack_chain_planner",
        true,
        chain.as_ref().map(|c| c.reached_goal).unwrap_or(false),
        chain.as_ref().map(|c| c.steps.len()).unwrap_or(0),
        chain
            .as_ref()
            .map(|c| c.mitre_path.join(">"))
            .unwrap_or_default(),
    ));

    // ── Case 6: Planner must NOT fabricate a chain when there is no evidence of exploitability ──
    let weak_findings = vec![serde_json::json!({
        "type": "info_banner",
        "title": "server header observed",
        "severity": "info",
        "verified": false
    })];
    let no_chain = plan_from_findings(&weak_findings, "impact:objective");
    report.push(BenchOutcome::new(
        "attack_chain_planner::no_fabrication",
        "attack_chain_planner",
        false,
        no_chain.is_some(),
        0,
        "must be None without evidence",
    ));

    // ── Case 7: Multi-stage correlation fires on a full intrusion progression ──
    let progression = vec![
        serde_json::json!({"mitre_attack":"T1595","type":"recon","title":"scan","severity":"info","target":"app.example.com"}),
        serde_json::json!({"mitre_attack":"T1190","type":"poe","title":"rce","severity":"critical","target":"app.example.com"}),
        serde_json::json!({"mitre_attack":"T1068","type":"privesc","title":"sudo abuse","severity":"high","target":"app.example.com"}),
        serde_json::json!({"mitre_attack":"T1567","type":"exfil","title":"db dump","severity":"critical","target":"app.example.com"}),
    ];
    let prog_events = events_from_findings(&progression, |i, _| 1000 + (i as i64) * 60);
    let prog_hits = evaluate_all(&default_rules(), &prog_events);
    report.push(BenchOutcome::new(
        "correlation::intrusion_progression",
        "correlation_rules",
        true,
        !prog_hits.is_empty(),
        prog_hits.len(),
        prog_hits
            .first()
            .map(|h| h.rule_id.clone())
            .unwrap_or_default(),
    ));

    // ── Case 8: Correlation must NOT fire on recon-only noise ──
    let noise = vec![
        serde_json::json!({"mitre_attack":"T1595","type":"recon","title":"scan a","severity":"info","target":"app.example.com"}),
        serde_json::json!({"mitre_attack":"T1595","type":"recon","title":"scan b","severity":"info","target":"app.example.com"}),
    ];
    let noise_events = events_from_findings(&noise, |i, _| 1000 + (i as i64) * 60);
    let noise_hits = evaluate_all(&default_rules(), &noise_events);
    report.push(BenchOutcome::new(
        "correlation::recon_only_no_fire",
        "correlation_rules",
        false,
        !noise_hits.is_empty(),
        noise_hits.len(),
        "recon-only must not correlate",
    ));

    // ── Cases 9–10: n-day template engine (exposed .git/config matcher logic) ──
    let git_tpl = builtin_templates()
        .into_iter()
        .find(|t| t.id == "exposed-git-config")
        .expect("builtin template present");
    let exposed = HttpResponseView {
        status: 200,
        headers: String::new(),
        body: "[core]\nrepositoryformatversion = 0".into(),
    };
    report.push(BenchOutcome::new(
        "template::git_config_exposed",
        "template_probe",
        true,
        git_tpl.evaluate(&exposed),
        1,
        "200 + [core]",
    ));
    let absent = HttpResponseView {
        status: 404,
        headers: String::new(),
        body: "[core]".into(),
    };
    report.push(BenchOutcome::new(
        "template::git_config_absent",
        "template_probe",
        false,
        git_tpl.evaluate(&absent),
        0,
        "404",
    ));

    // ── Cases 11–12: Sigma detection-as-code ──
    let sigma_rule = SigmaRule {
        id: "admin_attack".into(),
        title: "Attack reaching admin from untrusted source".into(),
        level: "high".into(),
        selections: vec![
            Selection::new(
                "sel",
                vec![FieldMatch::new("event", Op::Equals, &["attack"])],
            ),
            Selection::new(
                "filter",
                vec![FieldMatch::new("src", Op::Equals, &["trusted"])],
            ),
        ],
        condition: "sel and not filter".into(),
    };
    let malicious = serde_json::json!({"event":"attack","src":"internet"});
    let benign_evt = serde_json::json!({"event":"attack","src":"trusted"});
    report.push(BenchOutcome::new(
        "sigma::fires_on_untrusted_attack",
        "sigma_rules",
        true,
        !sigma_evaluate(
            std::slice::from_ref(&sigma_rule),
            std::slice::from_ref(&malicious),
        )
        .is_empty(),
        1,
        "sel and not filter",
    ));
    report.push(BenchOutcome::new(
        "sigma::suppressed_for_trusted",
        "sigma_rules",
        false,
        !sigma_evaluate(
            std::slice::from_ref(&sigma_rule),
            std::slice::from_ref(&benign_evt),
        )
        .is_empty(),
        0,
        "filtered by trusted source",
    ));

    // ── Cases 13–14: ITDR impossible travel ──
    let itdr_cfg = ItdrConfig::default();
    let travel = vec![
        AuthEvent::new(1000, "alice", "1.1.1.1", "US", true, false),
        AuthEvent::new(1600, "alice", "2.2.2.2", "DE", true, false),
    ];
    report.push(BenchOutcome::new(
        "itdr::impossible_travel",
        "itdr",
        true,
        !itdr_analyze(&travel, &itdr_cfg).is_empty(),
        1,
        "US->DE in 10m",
    ));
    let normal_login = vec![AuthEvent::new(0, "alice", "1.1.1.1", "US", true, false)];
    report.push(BenchOutcome::new(
        "itdr::single_login_ok",
        "itdr",
        false,
        !itdr_analyze(&normal_login, &itdr_cfg).is_empty(),
        0,
        "single login",
    ));

    let json = report.to_json();
    println!(
        "WEISSMAN_BENCHMARK_REPORT {}",
        serde_json::to_string_pretty(&json).expect("serialize report")
    );

    assert!(
        report.outcomes.iter().all(|o| o.correct()),
        "every benchmark case must classify correctly: {}",
        json
    );
    assert!(
        (report.repro_rate() - 1.0).abs() < 1e-9,
        "repro_rate must be 1.0 on the controlled corpus, got {}",
        report.repro_rate()
    );
    assert!(
        report.fp_rate() < 1e-9,
        "fp_rate must be 0.0 on the controlled corpus, got {}",
        report.fp_rate()
    );
}
