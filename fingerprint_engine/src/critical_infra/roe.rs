//! Rules of Engagement (RoE) preflight for critical-infrastructure engines.
//!
//! High-risk OT/ICS probes require explicit authorization before execution:
//! - `industrial_ot_enabled` on the client
//! - weaponized RoE mode **or** a cryptographically signed `critical_infra_contract`
//! - target on an explicit whitelist (client config, engagement scope, or signed contract)

use crate::engine_probes::extract_host;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{PgPool, Row};
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

struct EngagementRow {
    roe_mode: String,
    scope_snapshot: Value,
}

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

fn industrial_ot_enabled(config: &Value) -> bool {
    config
        .get("industrial_ot_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn roe_weaponized(config: &Value) -> bool {
    config
        .get("roe_mode")
        .and_then(Value::as_str)
        .is_some_and(|m| m.eq_ignore_ascii_case("weaponized_god_mode"))
}

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

fn push_trimmed(s: &str, out: &mut Vec<String>) {
    let t = s.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
}

fn dedupe_strings(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

fn merge_whitelists(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = a.to_vec();
    out.extend_from_slice(b);
    dedupe_strings(out)
}

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
    std::env::var("WEISSMAN_ROE_CONTRACT_SECRET")
        .ok()
        .or_else(|| std::env::var("WEISSMAN_JWT_SECRET").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

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
    let host = extract_host(target).to_ascii_lowercase();
    let target_lc = target.trim().to_ascii_lowercase();
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
        if e.starts_with("*.") {
            let suffix = e[1..].to_ascii_lowercase();
            if host.ends_with(&suffix) || target_lc.ends_with(&suffix) {
                return true;
            }
            continue;
        }
        let el = e.to_ascii_lowercase();
        if host == el || target_lc.contains(&el) {
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

fn dev_override_allowed(job_params: &Value) -> bool {
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
}
