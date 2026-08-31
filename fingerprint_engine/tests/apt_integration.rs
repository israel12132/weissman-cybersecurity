//! CI/CD integration tests: Hell's Gate / Halo's Gate latency, APT privilege-escalation
//! accuracy (0 fabricated findings), and NL-query / RAG injection blocking.

use fingerprint_engine::attack_chain_planner::{default_technique_library, plan};
use fingerprint_engine::engine_probes::empty_ok;
use fingerprint_engine::identity_engine::run_autonomous_privilege_escalation;
use fingerprint_engine::nl_query::{compile_plan, ingest_question, Filter, QueryPlan};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn assert_no_fabrication(findings: &[Value]) {
    for f in findings {
        let blob = f.to_string().to_ascii_lowercase();
        assert!(
            !blob.contains("fabrication_detected"),
            "finding must not carry fabrication_detected: {f}"
        );
        assert!(!blob.contains("lorem ipsum"), "placeholder text: {f}");
        assert!(
            !blob.contains("simulated_hit"),
            "simulated finding is forbidden: {f}"
        );
        assert!(
            !blob.contains("hardcoded_finding"),
            "hardcoded finding is forbidden: {f}"
        );
    }
}

/// Local HTTP listener that answers 200 with a JSON body containing **no** admin JWT.
/// Privilege-escalation must not invent a finding against this target.
async fn spawn_benign_http() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = b"{\"ok\":true,\"role\":\"user\"}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    std::str::from_utf8(body).unwrap_or("{}")
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn privilege_escalation_engine_emits_zero_findings_without_evidence() {
    let base = spawn_benign_http().await;
    let paths = vec![
        "register".into(),
        "admin".into(),
        "setup".into(),
        "users".into(),
    ];
    let start = Instant::now();
    // No LLM classifier → the hunter never POSTs mass-assignment payloads, and must
    // not fabricate a privilege-escalation finding from a 200 JSON user object.
    let (harvested, findings) =
        run_autonomous_privilege_escalation(&[base.clone()], &paths, None, None, None).await;
    let elapsed = start.elapsed();
    println!(
        "[CI/CD] APT priv-esc dry-run against {base}: harvested={} findings={} latency={elapsed:?}",
        harvested.len(),
        findings.len()
    );
    assert!(
        harvested.is_empty(),
        "no elevated token exists on the fixture — harvest must be empty, got {harvested:?}"
    );
    assert!(
        findings.is_empty(),
        "0 Fabricated Findings: benign localhost must not yield a priv-esc finding, got {findings:?}"
    );
    assert_no_fabrication(&findings);
}

#[test]
fn attack_chain_planner_does_not_fabricate_without_evidence() {
    let initial: HashSet<String> = ["service:web"].iter().map(|s| (*s).to_string()).collect();
    let chain = plan(
        &initial,
        &default_technique_library(),
        "impact:objective",
        50_000,
    );
    assert!(
        chain.is_none(),
        "planner must not fabricate a kill chain from a web service fact alone"
    );
}

#[test]
fn empty_ok_is_honest_success_with_zero_findings() {
    let r = empty_ok("identity_auto_harvest", "127.0.0.1");
    assert_eq!(r.status, "ok");
    assert!(r.findings.is_empty());
    assert!(r.message.contains("no live signal"));
    assert_no_fabrication(&r.findings);
}

#[test]
fn nl_query_blocks_sql_and_code_injection() {
    let payloads = [
        "SELECT * FROM weissman_app.secret_keys; -- Exploit",
        "'; DROP TABLE vulnerabilities; --",
        "UNION SELECT password_hash FROM users",
        "<script>fetch('/api/login')</script>",
        "javascript:alert(document.cookie)",
        "eval('db.query(\"select 1\")')",
        "1=1 OR pg_sleep(10)",
    ];
    for q in payloads {
        let err = ingest_question(q).expect_err(q);
        assert!(
            err.contains("rejected") || err.contains("SQL") || err.contains("injection"),
            "validator must reject {q:?}, got {err}"
        );
        // The rejected path never produces SQL.
        assert!(!err.to_ascii_lowercase().contains("from vulnerabilities"));
    }
}

#[test]
fn nl_query_json_plan_is_the_only_compile_path() {
    let json = r#"{"table":"vulnerabilities","select":["id","severity"],"filters":[{"column":"severity","op":"=","value":"critical"}],"limit":25}"#;
    assert!(
        ingest_question(json).is_err(),
        "unsigned JSON QueryPlan must not skip HMAC"
    );
    let plan: QueryPlan = serde_json::from_str(json).expect("plan");
    let key = [0x42u8; 32];
    let ts = fingerprint_engine::nl_query::queryplan_unix_now();
    let nonce = fingerprint_engine::nl_query::new_queryplan_nonce();
    let mac = fingerprint_engine::nl_query::sign_query_plan_with_key(&plan, &key, ts, &nonce)
        .expect("sign");
    let admitted = fingerprint_engine::nl_query::ingest_signed_query_plan_with_key(
        plan, &mac, ts, &nonce, &key,
    )
    .expect("hmac");
    let compiled = compile_plan(&admitted, 42).expect("compile");
    assert!(compiled
        .sql
        .starts_with("SELECT id, severity FROM vulnerabilities WHERE tenant_id = $1"));
    assert_eq!(compiled.params[0], Value::from(42));
    assert!(compiled.sql.contains("severity = $2"));
    assert!(!compiled.sql.contains("DROP"));
}

#[test]
fn nl_query_unknown_table_never_becomes_sql() {
    let plan = QueryPlan {
        table: "secret_keys".into(),
        select: vec!["*".into()],
        filters: vec![Filter {
            column: "id".into(),
            op: "=".into(),
            value: json!(1),
        }],
        order_by: None,
        order_desc: false,
        limit: Some(1),
        ..Default::default()
    };
    let err = compile_plan(&plan, 1).unwrap_err();
    assert!(err.contains("not exposed"));
}

#[test]
fn ingest_and_compile_latency_is_sub_millisecond() {
    let json = r#"{"table":"vulnerabilities","select":["id"],"filters":[],"limit":10}"#;
    let plan: QueryPlan = serde_json::from_str(json).expect("plan");
    let start = Instant::now();
    for _ in 0..1_000 {
        compile_plan(&plan, 1).unwrap();
    }
    let elapsed = start.elapsed();
    let per = elapsed / 1_000;
    assert!(
        per < Duration::from_millis(1),
        "compile_plan per-call {per:?} (batch {elapsed:?}) must be sub-millisecond"
    );
}

#[test]
fn nl_query_signed_plan_replay_and_skew_are_rejected() {
    let json = r#"{"table":"vulnerabilities","select":["id"],"filters":[],"limit":10}"#;
    let plan: QueryPlan = serde_json::from_str(json).expect("plan");
    let key = [0x7Au8; 32];
    let ts = fingerprint_engine::nl_query::queryplan_unix_now();
    let nonce = fingerprint_engine::nl_query::new_queryplan_nonce();
    let mac = fingerprint_engine::nl_query::sign_query_plan_with_key(&plan, &key, ts, &nonce)
        .expect("sign");
    fingerprint_engine::nl_query::ingest_signed_query_plan_with_key(
        plan.clone(),
        &mac,
        ts,
        &nonce,
        &key,
    )
    .expect("first admit");
    let replay = fingerprint_engine::nl_query::ingest_signed_query_plan_with_key(
        plan.clone(),
        &mac,
        ts,
        &nonce,
        &key,
    )
    .expect_err("replay");
    assert!(
        replay.contains("already been used"),
        "replay must fail, got {replay}"
    );

    let stale_ts = ts - fingerprint_engine::nl_query::QUERYPLAN_HMAC_MAX_SKEW_SECS - 1;
    let stale_nonce = fingerprint_engine::nl_query::new_queryplan_nonce();
    let stale_mac =
        fingerprint_engine::nl_query::sign_query_plan_with_key(&plan, &key, stale_ts, &stale_nonce)
            .expect("sign stale");
    let stale_err = fingerprint_engine::nl_query::verify_query_plan_hmac_with_key(
        &plan,
        &stale_mac,
        stale_ts,
        &stale_nonce,
        &key,
    )
    .expect_err("stale");
    assert!(
        stale_err.contains("timestamp"),
        "stale timestamp must fail, got {stale_err}"
    );
}
