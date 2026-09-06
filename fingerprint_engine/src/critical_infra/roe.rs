//! Rules of Engagement (RoE) preflight for critical-infrastructure engines.
//!
//! High-risk OT/ICS probes require explicit authorization before execution:
//! - `industrial_ot_enabled` on the client
//! - weaponized RoE mode **or** a cryptographically signed `critical_infra_contract`
//! - target on an explicit whitelist (client config, engagement scope, or signed contract)

use crate::engine_probes::extract_host;
use crate::engine_result::EngineResult;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
#[cfg(feature = "high_risk_engines")]
use sqlx::Row;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Inputs for RoE preflight — populated from dispatch context.
pub struct RoePreflightInput<'a> {
    pub pool: Option<&'a PgPool>,
    pub tenant_id: Option<i64>,
    pub client_id: Option<i64>,
    pub engine_id: &'a str,
    pub target: &'a str,
    pub job_params: &'a Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoeViolation {
    CompileTimeDisabled,
    MissingTenantContext,
    IndustrialOtDisabled,
    ProbeNotAuthorized,
    RoeModeInsufficient,
    TargetNotInScope,
    ContractExpired,
    ContractSignatureInvalid,
    NoActiveEngagement,
}

impl fmt::Display for RoeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompileTimeDisabled => {
                write!(f, "high_risk_engines feature not enabled on this binary")
            }
            Self::MissingTenantContext => {
                write!(f, "tenant_id and client_id required for critical infrastructure RoE")
            }
            Self::IndustrialOtDisabled => {
                write!(f, "industrial_ot_enabled is false — OT/ICS probing not authorized for client")
            }
            Self::ProbeNotAuthorized => write!(
                f,
                "critical_infra_probe_authorized not set — explicit operator authorization required"
            ),
            Self::RoeModeInsufficient => write!(
                f,
                "roe_mode must be weaponized_god_mode or a valid signed critical_infra_contract must be present"
            ),
            Self::TargetNotInScope => write!(
                f,
                "target is not on the critical-infrastructure whitelist"
            ),
            Self::ContractExpired => write!(f, "critical_infra_contract has expired"),
            Self::ContractSignatureInvalid => {
                write!(f, "critical_infra_contract signature verification failed")
            }
            Self::NoActiveEngagement => write!(
                f,
                "no active engagement with critical_infra_authorized scope"
            ),
        }
    }
}

/// Structured fail-closed result for a RoE denial. Findings stay empty; OT/ICS
/// probes never look like a completed empty scan.
#[must_use]
pub fn blocked_engine_result(
    engine: &str,
    target: &str,
    client_id: Option<i64>,
    violation: RoeViolation,
) -> EngineResult {
    let (control, control_value) = violation_control(violation);
    let roe = json!({
        "roe_blocked": true,
        "engine": engine,
        "target": target,
        "client_id": client_id,
        "violation": violation_name(violation),
        "detail": violation.to_string(),
        "control": control,
        "control_value": control_value,
        "auto_enable": false,
        "never_auto_enabled": true,
    });
    EngineResult::roe_blocked_with(
        format!("RoE blocked: {violation} — engine '{engine}' not authorized for target '{target}'"),
        Some(roe),
    )
}

fn violation_name(v: RoeViolation) -> &'static str {
    match v {
        RoeViolation::CompileTimeDisabled => "compile_time_disabled",
        RoeViolation::MissingTenantContext => "missing_tenant_context",
        RoeViolation::IndustrialOtDisabled => "industrial_ot_disabled",
        RoeViolation::ProbeNotAuthorized => "probe_not_authorized",
        RoeViolation::RoeModeInsufficient => "roe_mode_insufficient",
        RoeViolation::TargetNotInScope => "target_not_in_scope",
        RoeViolation::ContractExpired => "contract_expired",
        RoeViolation::ContractSignatureInvalid => "contract_signature_invalid",
        RoeViolation::NoActiveEngagement => "no_active_engagement",
    }
}

fn violation_control(v: RoeViolation) -> (&'static str, Value) {
    match v {
        RoeViolation::IndustrialOtDisabled => ("industrial_ot_enabled", json!(false)),
        RoeViolation::CompileTimeDisabled => ("high_risk_engines", json!(false)),
        RoeViolation::MissingTenantContext => ("tenant_and_client_id", Value::Null),
        RoeViolation::ProbeNotAuthorized => ("critical_infra_probe_authorized", json!(false)),
        RoeViolation::RoeModeInsufficient => ("roe_mode", json!("insufficient")),
        RoeViolation::TargetNotInScope => ("critical_infra_targets", Value::Null),
        RoeViolation::ContractExpired => ("critical_infra_contract", json!("expired")),
        RoeViolation::ContractSignatureInvalid => {
            ("critical_infra_contract", json!("invalid_signature"))
        }
        RoeViolation::NoActiveEngagement => ("engagement", Value::Null),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoeAuthority {
    SignedContract,
    ExplicitClientFlag,
    ActiveEngagement,
}

/// Run full RoE preflight. Returns `Ok(authority)` when execution may proceed.
pub async fn preflight(input: &RoePreflightInput<'_>) -> Result<RoeAuthority, RoeViolation> {
    #[cfg(not(feature = "high_risk_engines"))]
    {
        let _ = input;
        return Err(RoeViolation::CompileTimeDisabled);
    }

    #[cfg(feature = "high_risk_engines")]
    {
        preflight_live(input).await
    }
}

#[cfg(feature = "high_risk_engines")]
async fn preflight_live(input: &RoePreflightInput<'_>) -> Result<RoeAuthority, RoeViolation> {
    let (tenant_id, client_id) = match (input.tenant_id, input.client_id) {
        (Some(t), Some(c)) if t > 0 && c > 0 => (t, c),
        _ => {
            if dev_override_allowed(input.job_params) {
                return Ok(RoeAuthority::ExplicitClientFlag);
            }
            return Err(RoeViolation::MissingTenantContext);
        }
    };

    let client_configs = load_client_configs(input.pool, tenant_id, client_id).await;
    let engagement = load_active_engagement(input.pool, tenant_id, client_id).await;

    if !industrial_ot_enabled(&client_configs) {
        return Err(RoeViolation::IndustrialOtDisabled);
    }

    let whitelist = build_target_whitelist(&client_configs, engagement.as_ref());

    // Signed contract path — cryptographically bound targets + expiry.
    if let Some(contract) = client_configs
        .get("critical_infra_contract")
        .or_else(|| input.job_params.get("critical_infra_contract"))
    {
        match verify_signed_contract(contract, input.target, &whitelist) {
            Ok(()) => return Ok(RoeAuthority::SignedContract),
            Err(RoeViolation::ContractSignatureInvalid) => {
                return Err(RoeViolation::ContractSignatureInvalid);
            }
            Err(RoeViolation::ContractExpired) => return Err(RoeViolation::ContractExpired),
            Err(RoeViolation::TargetNotInScope) => {
                return Err(RoeViolation::TargetNotInScope);
            }
            Err(other) => return Err(other),
        }
    }

    // Explicit client flag + weaponized RoE.
    let weaponized = roe_weaponized(&client_configs);
    let probe_authorized = client_configs
        .get("critical_infra_probe_authorized")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if probe_authorized && weaponized {
        if target_in_whitelist(input.target, &whitelist) {
            return Ok(RoeAuthority::ExplicitClientFlag);
        }
        return Err(RoeViolation::TargetNotInScope);
    }

    // Active engagement with critical_infra_authorized in scope_snapshot.
    if let Some(eng) = engagement {
        if eng.roe_mode == "weaponized_god_mode" {
            let scope_auth = eng
                .scope_snapshot
                .get("critical_infra_authorized")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if scope_auth {
                let eng_whitelist = scope_targets(&eng.scope_snapshot);
                let combined = merge_whitelists(&whitelist, &eng_whitelist);
                if target_in_whitelist(input.target, &combined) {
                    return Ok(RoeAuthority::ActiveEngagement);
                }
                return Err(RoeViolation::TargetNotInScope);
            }
        }
    }

    if !weaponized {
        return Err(RoeViolation::RoeModeInsufficient);
    }
    if !probe_authorized {
        return Err(RoeViolation::ProbeNotAuthorized);
    }
    Err(RoeViolation::NoActiveEngagement)
}

/// Forensic violation log — always emitted; audit row when DB is available.
pub async fn log_violation(
    pool: Option<&PgPool>,
    tenant_id: Option<i64>,
    client_id: Option<i64>,
    engine_id: &str,
    target: &str,
    violation: RoeViolation,
) {
    tracing::error!(
        target: "critical_infra_roe",
        violation = %violation,
        engine_id = %engine_id,
        probe_target = %target,
        tenant_id = ?tenant_id,
        client_id = ?client_id,
        "RoE VIOLATION — critical infrastructure engine execution blocked"
    );

    let Some(pool) = pool else { return };
    let Some(tid) = tenant_id.filter(|&t| t > 0) else {
        return;
    };

    let details = format!(
        "engine={} target={} violation={} client_id={:?}",
        engine_id, target, violation, client_id
    );
    if let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tid).await {
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            tid,
            None,
            "system:roe_gate",
            "critical_infra_roe_violation",
            &details,
            "0.0.0.0",
        )
        .await;
        let _ = tx.commit().await;
    }
}

// The helpers below are used only by `preflight_live`, which is gated on the
// `high_risk_engines` feature; gate them identically so a default build (feature
// off) doesn't compile — and warn about — code it can never reach.
#[cfg(feature = "high_risk_engines")]
struct EngagementRow {
    roe_mode: String,
    scope_snapshot: Value,
}

#[cfg(feature = "high_risk_engines")]
async fn load_client_configs(pool: Option<&PgPool>, tenant_id: i64, client_id: i64) -> Value {
    let Some(pool) = pool else {
        return Value::Object(serde_json::Map::new());
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Value::Object(serde_json::Map::new());
    };
    let row = sqlx::query(
        "SELECT COALESCE(NULLIF(trim(client_configs), ''), '{}') AS client_configs \
         FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(client_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let Some(r) = row else {
        return Value::Object(serde_json::Map::new());
    };
    let raw: String = r
        .try_get("client_configs")
        .unwrap_or_else(|_| "{}".to_string());
    serde_json::from_str(&raw).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

#[cfg(feature = "high_risk_engines")]
async fn load_active_engagement(
    pool: Option<&PgPool>,
    tenant_id: i64,
    client_id: i64,
) -> Option<EngagementRow> {
    let pool = pool?;
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return None;
    };
    let row = sqlx::query(
        r#"SELECT roe_mode, scope_snapshot FROM engagements
           WHERE tenant_id = $1 AND client_id = $2 AND status = 'active'
             AND (end_at IS NULL OR end_at > now())
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    row.map(|r| EngagementRow {
        roe_mode: r
            .try_get("roe_mode")
            .unwrap_or_else(|_| "safe_proofs".to_string()),
        scope_snapshot: r
            .try_get::<Value, _>("scope_snapshot")
            .unwrap_or_else(|_| json!({})),
    })
}

#[cfg(feature = "high_risk_engines")]
fn industrial_ot_enabled(config: &Value) -> bool {
    config
        .get("industrial_ot_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(feature = "high_risk_engines")]
fn roe_weaponized(config: &Value) -> bool {
    config
        .get("roe_mode")
        .and_then(Value::as_str)
        .is_some_and(|m| m.eq_ignore_ascii_case("weaponized_god_mode"))
}

#[cfg(feature = "high_risk_engines")]
fn build_target_whitelist(
    client_configs: &Value,
    engagement: Option<&EngagementRow>,
) -> Vec<String> {
    let mut out = Vec::new();
    collect_string_list(client_configs, "critical_infra_targets", &mut out);
    collect_string_list(client_configs, "scope_ips", &mut out);
    collect_string_list(client_configs, "ip_ranges", &mut out);
    collect_string_list(client_configs, "domains", &mut out);
    if let Some(onb) = client_configs.get("onboarding") {
        collect_string_list(onb, "scope_ips", &mut out);
        collect_string_list(onb, "ip_ranges", &mut out);
        collect_string_list(onb, "domains", &mut out);
    }
    if let Some(eng) = engagement {
        out.extend(scope_targets(&eng.scope_snapshot));
    }
    dedupe_strings(out)
}

#[cfg(feature = "high_risk_engines")]
fn scope_targets(scope: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_string_list(scope, "allowed_targets", &mut out);
    collect_string_list(scope, "critical_infra_targets", &mut out);
    collect_string_list(scope, "ip_ranges", &mut out);
    collect_string_list(scope, "domains", &mut out);
    if let Some(arr) = scope.get("targets").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                push_trimmed(s, &mut out);
            }
        }
    }
    out
}

#[cfg(feature = "high_risk_engines")]
fn collect_string_list(obj: &Value, key: &str, out: &mut Vec<String>) {
    let Some(arr) = obj.get(key).and_then(Value::as_array) else {
        return;
    };
    for v in arr {
        if let Some(s) = v.as_str() {
            push_trimmed(s, out);
        }
    }
}

#[cfg(feature = "high_risk_engines")]
fn push_trimmed(s: &str, out: &mut Vec<String>) {
    let t = s.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
}

#[cfg(feature = "high_risk_engines")]
fn dedupe_strings(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

#[cfg(feature = "high_risk_engines")]
fn merge_whitelists(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = a.to_vec();
    out.extend_from_slice(b);
    dedupe_strings(out)
}

#[cfg(feature = "high_risk_engines")]
fn verify_signed_contract(
    contract: &Value,
    target: &str,
    fallback_whitelist: &[String],
) -> Result<(), RoeViolation> {
    let authorized = contract
        .get("authorized")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !authorized {
        return Err(RoeViolation::ProbeNotAuthorized);
    }

    let expires = contract
        .get("expires_unix")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if expires > 0 {
        let now = chrono::Utc::now().timestamp();
        if now > expires {
            return Err(RoeViolation::ContractExpired);
        }
    }

    let sig = contract
        .get("sig")
        .or_else(|| contract.get("signature"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if sig.is_empty() {
        return Err(RoeViolation::ContractSignatureInvalid);
    }

    let mut targets: Vec<String> = Vec::new();
    if let Some(arr) = contract.get("targets").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                push_trimmed(s, &mut targets);
            }
        }
    }
    if targets.is_empty() {
        targets = fallback_whitelist.to_vec();
    }

    let canonical = contract_canonical_payload(contract, &targets);
    if !verify_hmac(&canonical, sig) {
        return Err(RoeViolation::ContractSignatureInvalid);
    }

    if !target_in_whitelist(target, &targets) {
        return Err(RoeViolation::TargetNotInScope);
    }
    Ok(())
}

// Also exercised by unit tests under default features, so keep it available for `test`.
#[cfg(any(feature = "high_risk_engines", test))]
fn contract_canonical_payload(contract: &Value, targets: &[String]) -> String {
    let v = contract.get("v").and_then(Value::as_i64).unwrap_or(1);
    let expires = contract
        .get("expires_unix")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let mut sorted = targets.to_vec();
    sorted.sort();
    let joined = sorted.join(",");
    format!("v{v}|authorized=true|expires={expires}|targets={joined}")
}

fn signing_secret() -> Option<String> {
    // Prefer a dedicated RoE contract key so a leak of the auth-token secret cannot forge
    // authorization contracts (key separation).
    if let Ok(s) = std::env::var("WEISSMAN_ROE_CONTRACT_SECRET") {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    // Fallback to the JWT secret keeps an operator who only set WEISSMAN_JWT_SECRET working,
    // but reusing it for authorization-contract signing breaks key separation — warn once.
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            target: "critical_infra_roe",
            "WEISSMAN_ROE_CONTRACT_SECRET not set — falling back to WEISSMAN_JWT_SECRET for RoE \
             contract signing. Set a dedicated key to isolate authorization signing from auth tokens."
        );
    });
    std::env::var("WEISSMAN_JWT_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(feature = "high_risk_engines")]
fn verify_hmac(canonical: &str, sig_hex: &str) -> bool {
    let Some(secret) = signing_secret() else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(canonical.as_bytes());
    let expected = mac.finalize().into_bytes();
    let Ok(provided) = hex::decode(sig_hex.trim()) else {
        return false;
    };
    if provided.len() != expected.len() {
        return false;
    }
    // Constant-time compare
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[must_use]
pub fn target_in_whitelist(target: &str, whitelist: &[String]) -> bool {
    if whitelist.is_empty() {
        return false;
    }
    if whitelist.iter().any(|e| e == "*" || e == "0.0.0.0/0") {
        return true;
    }
    // All matching is done against the extracted host only — never against a
    // substring/suffix of the full target URL. A substring/suffix match on the raw
    // target lets an attacker smuggle a whitelisted host into the path/query of an
    // out-of-scope URL (e.g. whitelist `grid.example.com` would authorize
    // `http://evil.com/?ref=grid.example.com`, or `*.hospital.internal` would match
    // `http://evil.com/x.hospital.internal`). Host-equality and true subdomain
    // suffix are the only safe predicates.
    let host = extract_host(target).to_ascii_lowercase();
    for entry in whitelist {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if e.contains('/') {
            if cidr_contains_host(e, &host) {
                return true;
            }
            continue;
        }
        if let Some(bare) = e.strip_prefix("*.") {
            let suffix = format!(".{}", bare.to_ascii_lowercase());
            if host.ends_with(&suffix) {
                return true;
            }
            continue;
        }
        let el = e.to_ascii_lowercase();
        if host == el || host.ends_with(&format!(".{el}")) {
            return true;
        }
    }
    false
}

fn cidr_contains_host(cidr: &str, host: &str) -> bool {
    let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() else {
        return false;
    };
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return false;
    };
    net.contains(ip)
}

#[cfg(feature = "high_risk_engines")]
fn dev_override_allowed(job_params: &Value) -> bool {
    // Hard compile-time guard: the RoE scope bypass can NEVER exist in a release
    // build, regardless of environment variables. Production images are built in
    // release mode, so this branch compiles the override out entirely.
    #[cfg(not(debug_assertions))]
    {
        let _ = job_params;
        false
    }
    #[cfg(debug_assertions)]
    {
        // Belt-and-suspenders: even in a debug build, refuse the override if the
        // process considers itself production.
        if weissman_core::tls_policy::is_production_environment() {
            return false;
        }
        if !std::env::var("WEISSMAN_CRITICAL_INFRA_DEV_OVERRIDE")
            .ok()
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        {
            return false;
        }
        job_params
            .get("critical_infra_roe_dev_override")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

/// Compute HMAC signature for a contract payload (operator tooling / tests).
#[must_use]
pub fn sign_contract_payload(canonical: &str) -> Option<String> {
    let secret = signing_secret()?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(canonical.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn target_whitelist_host_and_cidr() {
        let wl = vec!["10.0.0.0/8".to_string(), "grid.lab.example.com".to_string()];
        assert!(target_in_whitelist("10.0.1.5", &wl));
        assert!(target_in_whitelist("https://grid.lab.example.com/", &wl));
        assert!(!target_in_whitelist("192.168.1.1", &wl));
    }

    #[test]
    fn wildcard_domain_match() {
        let wl = vec!["*.hospital.internal".to_string()];
        assert!(target_in_whitelist("icu.hospital.internal", &wl));
        assert!(!target_in_whitelist("evil.com", &wl));
    }

    #[test]
    fn substring_smuggling_is_rejected() {
        // A whitelisted host must not be matchable as a substring/suffix of an
        // out-of-scope target's path, query, or hostname.
        let wl = vec!["grid.example.com".to_string()];
        assert!(!target_in_whitelist(
            "http://evil.com/?ref=grid.example.com",
            &wl
        ));
        assert!(!target_in_whitelist(
            "http://grid.example.com.evil.com/",
            &wl
        ));
        assert!(target_in_whitelist("https://grid.example.com/status", &wl));
        assert!(target_in_whitelist("https://sub.grid.example.com/", &wl));

        let wc = vec!["*.hospital.internal".to_string()];
        assert!(!target_in_whitelist(
            "http://evil.com/x.hospital.internal",
            &wc
        ));
        assert!(target_in_whitelist("https://icu.hospital.internal/", &wc));
    }

    #[test]
    fn scope_invariant_over_adversarial_targets() {
        // Systematic invariant sweep: a target is authorized IFF its extracted host equals a
        // plain entry, is a true dot-subdomain of one, matches a wildcard suffix, or is inside a
        // CIDR — NEVER via substring/path/query/userinfo/fragment smuggling.
        let wl = vec![
            "approved.example.com".to_string(),
            "*.wild.example.org".to_string(),
            "10.0.0.0/8".to_string(),
        ];
        for t in [
            "approved.example.com",
            "https://approved.example.com/x",
            "http://approved.example.com:8443/",
            "sub.approved.example.com",
            "deep.sub.approved.example.com",
            "icu.wild.example.org",
            "10.0.0.1",
            "10.255.255.254",
        ] {
            assert!(target_in_whitelist(t, &wl), "should be IN scope: {t}");
        }
        for t in [
            "evil.com",
            "approved.example.com.evil.com",
            "http://evil.com/?x=approved.example.com",
            "http://evil.com/approved.example.com",
            "http://evil.com#approved.example.com",
            "http://approved.example.com@evil.com/",
            "http://evil.com/wild.example.org",
            "wild.example.org.evil.com",
            "notapproved.example.com",
            "xapproved.example.com",
            "192.168.1.1",
            "11.0.0.1",
            "9.255.255.255",
        ] {
            assert!(!target_in_whitelist(t, &wl), "must be OUT of scope: {t}");
        }
    }

    #[test]
    fn contract_canonical_stable() {
        let c = json!({"v": 1, "expires_unix": 1893456000});
        let t = vec!["b.example.com".to_string(), "10.0.0.1".to_string()];
        let p = contract_canonical_payload(&c, &t);
        assert_eq!(
            p,
            "v1|authorized=true|expires=1893456000|targets=10.0.0.1,b.example.com"
        );
    }

    #[test]
    fn empty_whitelist_denies() {
        assert!(!target_in_whitelist("10.0.0.1", &[]));
    }

    #[test]
    fn industrial_ot_disabled_is_structured_block() {
        let r = blocked_engine_result(
            "smart_grid_dlms_attack",
            "10.0.0.1",
            Some(42),
            RoeViolation::IndustrialOtDisabled,
        );
        assert_eq!(r.status, "roe_blocked");
        assert!(r.roe_blocked);
        assert!(r.findings.is_empty());
        let roe = r.roe.as_ref().expect("roe");
        assert_eq!(roe["control"], json!("industrial_ot_enabled"));
        assert_eq!(roe["control_value"], json!(false));
        assert_eq!(roe["auto_enable"], json!(false));
        assert_eq!(roe["never_auto_enabled"], json!(true));
    }
}
