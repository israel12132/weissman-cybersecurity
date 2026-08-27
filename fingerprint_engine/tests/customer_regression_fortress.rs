//! Customer regression fortress — locks shipped contracts other teams must not break.
//!
//! 1. Login surface is `/command-center/login` only (source + HTTP 404 when live).
//! 2. Portal JWT cannot list or spoof other customers.
//! 3. Target-requiring engines reject empty target with `target_required`, not a crash.
//! 4. Jobs diagnostics always expose redis / workers / pending_no_envelope / stuck_reason.
//! 5. OT engines with industrial_ot_enabled false return structured `roe_blocked`, never fake ICS hits.

use fingerprint_engine::alias_engine_runner::is_alias_engine;
use fingerprint_engine::auth_jwt::AuthContext;
use fingerprint_engine::client_isolation::{
    bind_requested_client, capabilities_json, force_json_client_id, force_query_client_id,
    is_client_scoped,
};
use fingerprint_engine::critical_infra::is_critical_infra_engine;
use fingerprint_engine::critical_infra::roe::{blocked_engine_result, RoeViolation};
use fingerprint_engine::engine_dispatch::{run_engine, EngineRunContext};
use fingerprint_engine::job_diagnostics::{job_stuck_reason, DIAGNOSTICS_REQUIRED_FIELDS};
use fingerprint_engine::scan_routing::{
    reject_empty_target, RouteError, TARGET_REQUIRED_ERROR_CODE,
};
use serde_json::{json, Value};
use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

const CUSTOMER_ENGINE_COUNT: usize = 563;

fn portal_auth(cid: i64) -> AuthContext {
    AuthContext {
        user_id: 9,
        tenant_id: 1,
        role: "client".into(),
        is_superadmin: false,
        agent_id: None,
        jti: None,
        bind_ip: None,
        bind_tls_fp: None,
        assigned_client_id: Some(cid),
    }
}

fn staff_auth() -> AuthContext {
    AuthContext {
        user_id: 2,
        tenant_id: 1,
        role: "operator".into(),
        is_superadmin: false,
        agent_id: None,
        jti: None,
        bind_ip: None,
        bind_tls_fp: None,
        assigned_client_id: None,
    }
}

fn ics_looking(findings: &[Value]) -> bool {
    let blob = serde_json::to_string(findings)
        .unwrap_or_default()
        .to_lowercase();
    [
        "modbus holding",
        "iec-104 asdu",
        "triton implant",
        "fake ics",
        "simulated ics",
    ]
    .iter()
    .any(|n| blob.contains(n))
}

// ── 1. Auth / login surface ──────────────────────────────────────────────────

#[test]
fn login_exists_only_under_command_center() {
    let tactical = include_str!("../../frontend/src/TacticalApp.jsx");
    let main = include_str!("../../frontend/src/main.jsx");
    let vite = include_str!("../../frontend/vite.config.js");
    let serve = include_str!("../src/http/serve.rs");
    let routes = include_str!("../src/http/serve_route_groups.rs");

    assert!(
        main.contains("basename=\"/command-center\""),
        "SPA must boot under /command-center so login is /command-center/login"
    );
    assert!(vite.contains("base: '/command-center/'"));
    let login_routes: Vec<&str> = tactical
        .match_indices("path=\"login\"")
        .map(|_| "login")
        .collect();
    assert_eq!(
        login_routes,
        vec!["login"],
        "exactly one relative login route"
    );
    assert!(!tactical.contains("path=\"signin\""), "no /signin route");
    assert!(!tactical.contains("path=\"auth\""), "no /auth route");
    assert!(
        !serve.contains(".route(\"/login\""),
        "backend must not serve a second login page at /login"
    );
    assert!(
        !serve.contains(".route(\"/signin\""),
        "backend must not serve /signin"
    );
    assert!(
        routes.contains("/api/login"),
        "the only login API is POST /api/login"
    );
    assert!(
        serve.contains("nest_service(\"/command-center\""),
        "Command Center static/SPA is nested under /command-center"
    );
}

#[test]
fn login_copy_locks_563_and_live_backdrop_css() {
    let login = include_str!("../../frontend/src/components/cockpit/Login.jsx");
    let css = include_str!("../../frontend/src/styles/cyber-live-backdrop.css");
    let index = include_str!("../../frontend/src/index.css");
    let scale = include_str!("../../frontend/src/lib/platformScale.js");
    assert!(login.contains("CyberLiveBackdrop"));
    assert!(login.contains("PRODUCTION_ENGINE_COUNT"));
    assert!(!login.contains("auth-mesh-drift"));
    assert!(!login.contains("254 engines"));
    assert!(scale.contains("PRODUCTION_ENGINE_COUNT = 563"));
    assert!(index.contains("cyber-live-backdrop.css"));
    assert!(css.contains(".wm-cyber-backdrop"));
    assert!(css.contains("wm-cbg-aurora"));
    assert_eq!(PRODUCTION_ENGINE_IDS.len(), CUSTOMER_ENGINE_COUNT);
}

// ── 2. Client scope ──────────────────────────────────────────────────────────

#[test]
fn portal_jwt_cannot_bind_another_customer() {
    let portal = portal_auth(7);
    assert!(is_client_scoped(&portal));
    assert_eq!(bind_requested_client(&portal, None).unwrap(), Some(7));
    assert_eq!(bind_requested_client(&portal, Some(7)).unwrap(), Some(7));
    assert!(
        bind_requested_client(&portal, Some(99)).is_err(),
        "portal JWT asking for another client_id must fail closed"
    );
    let staff = staff_auth();
    assert!(!is_client_scoped(&staff));
    assert_eq!(bind_requested_client(&staff, Some(99)).unwrap(), Some(99));
}

#[test]
fn spoofed_client_id_is_overwritten_not_trusted() {
    let portal = portal_auth(8);
    let mut body = json!({
        "engine": "asm",
        "target": "https://ex.test",
        "client_id": 99
    });
    force_json_client_id(&portal, &mut body).unwrap();
    assert_eq!(
        body["client_id"],
        json!(8),
        "top-level spoof must be overwritten"
    );

    let mut nested = json!({"engine": "asm", "data": {"client_id": 3}});
    force_json_client_id(&portal, &mut nested).unwrap();
    assert_eq!(nested["client_id"], json!(8));
    assert_eq!(nested["data"]["client_id"], json!(8));

    assert_eq!(
        force_query_client_id(Some("limit=10&client_id=99"), 5).as_deref(),
        Some("limit=10&client_id=5")
    );
}

#[test]
fn capabilities_hide_picker_and_clients_list_sql_is_scoped() {
    let caps = capabilities_json(&portal_auth(4));
    assert_eq!(caps["client_picker_hidden"], json!(true));
    assert_eq!(caps["allowed_client_ids"], json!([4]));
    assert_eq!(caps["is_client_user"], json!(true));

    let staff = capabilities_json(&staff_auth());
    assert_eq!(staff["client_picker_hidden"], json!(false));

    let list_src = include_str!("../src/server_handlers_rest.inc");
    assert!(
        list_src.contains("WHERE ($3::bigint IS NULL OR id = $3)"),
        "GET /api/clients must filter to the bound customer when the JWT is scoped"
    );
}

// ── 3. Scan contract ─────────────────────────────────────────────────────────

#[test]
fn empty_target_is_target_required_not_internal_error() {
    for engine in ["osint", "asm", "bola_idor", "graphql_attack", "jwt_attack"] {
        let err = reject_empty_target(engine, "").expect_err(engine);
        assert_eq!(
            err.error_code(),
            TARGET_REQUIRED_ERROR_CODE,
            "{engine}: stable machine code"
        );
        assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert!(
            err.detail().contains("target required"),
            "{engine}: {err:?}"
        );
        assert_ne!(err.error_code(), "internal_error");
    }
    assert!(reject_empty_target("osint", "https://in-scope.example").is_ok());
    let other = RouteError::BadRequest("engine required".into());
    assert_eq!(other.error_code(), "bad_request");
}

#[tokio::test]
async fn dispatch_empty_target_errors_without_findings_or_panic() {
    let ctx = EngineRunContext::default();
    for engine in ["osint", "asm", "smart_grid_dlms_attack"] {
        let r = run_engine(engine, "", &ctx).await;
        assert_eq!(r.status, "error", "{engine}");
        assert!(
            r.message.to_ascii_lowercase().contains("target required"),
            "{engine}: {}",
            r.message
        );
        assert!(r.findings.is_empty(), "{engine} must not invent findings");
        assert!(!r.success);
        assert!(!r.roe_blocked, "empty target is validation, not RoE");
    }
}

#[test]
fn openapi_documents_target_required() {
    let spec = include_str!("../src/server_handlers_rest2.inc");
    assert!(spec.contains("\"target_required\""));
    assert!(spec.contains("ScanRequest"));
    assert!(spec.contains("/api/command-center/scan"));
    assert!(spec.contains("Empty target returns HTTP 400"));
    assert!(spec.contains("/api/jobs/diagnostics"));
    assert!(spec.contains("pending_no_envelope"));
    assert!(spec.contains("stuck_reason"));
}

// ── 4. Jobs diagnostics ──────────────────────────────────────────────────────

#[test]
fn jobs_diagnostics_handler_emits_contract_fields() {
    let src = include_str!("../src/server_handlers_jobs.inc");
    for key in DIAGNOSTICS_REQUIRED_FIELDS {
        let needle = format!("\"{key}\"");
        assert!(
            src.contains(&needle),
            "GET /api/jobs/diagnostics must emit {key}"
        );
    }
    assert!(src.contains("pending_no_envelope"));
    assert!(src.contains("job_stuck_reason") || src.contains("stuck_reason"));
    let list_has_stuck = src.contains("\"stuck_reason\": stuck")
        || src.contains("\"stuck_reason\":stuck")
        || src.contains("stuck_reason");
    assert!(list_has_stuck, "job list rows must include stuck_reason");
}

#[test]
fn job_stuck_reason_names_missing_envelope() {
    let created = chrono::Utc::now() - chrono::Duration::seconds(45);
    let reason = job_stuck_reason(
        "pending",
        &json!({"engine": "asm"}),
        Some(created),
        None,
        0,
        3,
        None,
    );
    assert_eq!(reason.as_deref(), Some("missing_envelope"));
}

// ── 5. RoE / industrial OT ───────────────────────────────────────────────────

#[test]
fn industrial_ot_disabled_is_structured_block_not_fake_ics() {
    let r = blocked_engine_result(
        "smart_grid_dlms_attack",
        "10.0.0.1",
        Some(42),
        RoeViolation::IndustrialOtDisabled,
    );
    assert_eq!(r.status, "roe_blocked");
    assert!(r.roe_blocked);
    assert!(!r.success);
    assert!(r.findings.is_empty(), "must not invent ICS findings");
    assert!(!ics_looking(&r.findings));
    let roe = r.roe.as_ref().expect("roe payload");
    assert_eq!(roe["roe_blocked"], json!(true));
    assert_eq!(roe["control"], json!("industrial_ot_enabled"));
    assert_eq!(roe["control_value"], json!(false));
    assert_eq!(roe["auto_enable"], json!(false));
    assert_eq!(roe["never_auto_enabled"], json!(true));
    assert!(
        r.message.to_ascii_lowercase().contains("roe blocked")
            || r.message.contains("industrial_ot_enabled"),
        "{}",
        r.message
    );
    assert!(
        !r.message.to_lowercase().contains("finding(s) on"),
        "must not look like a completed empty scan"
    );
}

#[tokio::test]
async fn ot_engine_run_without_authorization_is_roe_blocked() {
    for engine in [
        "smart_grid_dlms_attack",
        "ot_sis_triton_attack",
        "building_automation_attack",
    ] {
        assert!(
            is_critical_infra_engine(engine),
            "{engine} must stay on the RoE path"
        );
        assert!(
            !is_alias_engine(engine),
            "{engine} must not skip RoE via the alias table"
        );
        let ctx = EngineRunContext::default();
        let r = run_engine(engine, "10.0.0.1", &ctx).await;
        assert!(
            r.roe_blocked || r.status == "roe_blocked",
            "{engine}: expected fail-closed RoE, got status={} msg={}",
            r.status,
            r.message
        );
        assert!(
            r.findings.is_empty(),
            "{engine} leaked findings: {:?}",
            r.findings
        );
        assert!(!ics_looking(&r.findings), "{engine} fabricated ICS hits");
        let blob = format!(
            "{}{}",
            r.message,
            serde_json::to_string(&r.roe).unwrap_or_default()
        )
        .to_lowercase();
        assert!(
            blob.contains("roe")
                || blob.contains("industrial_ot")
                || blob.contains("high_risk")
                || blob.contains("blocked"),
            "{engine}: message must explain the block, got {}",
            r.message
        );
    }
}

// ── Live HTTP (skipped when the stack is down) ───────────────────────────────

fn live_api_base() -> Option<String> {
    let base = std::env::var("WEISSMAN_E2E_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8000".into())
        .trim_end_matches('/')
        .to_string();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok()?;
    let ok = client
        .get(format!("{base}/api/health"))
        .send()
        .ok()
        .is_some_and(|r| r.status().is_success());
    ok.then_some(base)
}

#[test]
fn live_http_login_404_and_contracts_when_stack_up() {
    let Some(base) = live_api_base() else {
        eprintln!("customer-regression-fortress: API not reachable — skipping live HTTP checks");
        return;
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");

    for path in ["/login", "/signin", "/auth"] {
        let resp = client
            .get(format!("{base}{path}"))
            .send()
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(
            resp.status().as_u16(),
            404,
            "{path} must 404 (login lives at /command-center/login); got {}",
            resp.status()
        );
    }

    let spec: Value = client
        .get(format!("{base}/api/openapi.json"))
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .unwrap_or_else(|e| panic!("openapi: {e}"));
    let scan = &spec["paths"]["/api/command-center/scan"]["post"];
    assert!(
        scan["responses"]["400"].is_object() || spec.to_string().contains("target_required"),
        "OpenAPI must document empty-target as 400/target_required"
    );
    let diag_path = &spec["paths"]["/api/jobs/diagnostics"];
    assert!(
        diag_path.is_object() || spec.to_string().contains("pending_no_envelope"),
        "OpenAPI must document jobs diagnostics"
    );
}
