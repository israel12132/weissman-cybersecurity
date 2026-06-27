//! **Identity Attack Chain** — live fusion of Kerberos posture + password spray + ITDR auth events.
//!
//! Correlates credential spray signals, Kerberos attack surface, and ingested identity telemetry
//! into a unified identity kill-chain narrative. Evidence-only — no simulated findings.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use sqlx::Row;

const ENGINE_ID: &str = "identity_attack_chain";

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn finding_severity(f: &Value) -> &str {
    f.get("severity").and_then(Value::as_str).unwrap_or("info")
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn haystack(f: &Value) -> String {
    format!(
        "{} {} {}",
        f.get("title").and_then(Value::as_str).unwrap_or(""),
        f.get("description").and_then(Value::as_str).unwrap_or(""),
        f.get("category").and_then(Value::as_str).unwrap_or(""),
    )
    .to_lowercase()
}

fn has_signal(findings: &[Value], keywords: &[&str]) -> bool {
    findings
        .iter()
        .any(|f| keywords.iter().any(|k| haystack(f).contains(k)))
}

fn ingest_source(
    merged: &mut Vec<Value>,
    penalty: &mut u32,
    label: &str,
    result: &EngineResult,
) -> bool {
    if !result.success || result.findings.is_empty() {
        return false;
    }
    for mut f in result.findings.clone() {
        if let Some(obj) = f.as_object_mut() {
            obj.entry("source_engine".to_string())
                .or_insert(json!(label));
            obj.entry("fusion_engine".to_string())
                .or_insert(json!(ENGINE_ID));
        }
        *penalty += match severity_rank(finding_severity(&f)) {
            4 => 12,
            3 => 7,
            2 => 3,
            1 => 1,
            _ => 0,
        };
        merged.push(f);
    }
    true
}

async fn itdr_findings_from_db(ctx: &EngineRunContext, host: &str) -> Vec<Value> {
    let (pool, tenant_id, client_id) = match (
        ctx.app_pool.as_ref(),
        ctx.tenant_id,
        ctx.client_id,
    ) {
        (Some(p), Some(t), Some(c)) => (p.as_ref(), t, c),
        _ => return Vec::new(),
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Vec::new();
    };
    let rows = sqlx::query(
        r#"SELECT ts, username, ip, country, success, mfa_prompted
             FROM itdr_auth_events
            WHERE client_id = $1
            ORDER BY id DESC LIMIT 40"#,
    )
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let mut out = Vec::new();
    for r in rows {
        let username = r.try_get::<String, _>("username").unwrap_or_default();
        let ip = r.try_get::<String, _>("ip").unwrap_or_default();
        let success = r.try_get::<bool, _>("success").unwrap_or(false);
        let mfa = r.try_get::<bool, _>("mfa_prompted").unwrap_or(false);
        if success && mfa {
            continue;
        }
        let sev = if !success && !mfa {
            "high"
        } else if !success {
            "medium"
        } else {
            "low"
        };
        let event_label = if !success {
            "failed_auth"
        } else {
            "auth_without_mfa"
        };
        let mut f = finding(
            ENGINE_ID,
            &format!("ITDR auth signal — {event_label}"),
            sev,
            "T1078",
            &format!(
                "Live identity telemetry: user={username} ip={ip} success={success} mfa={mfa}"
            ),
            host,
        );
        if let Some(obj) = f.as_object_mut() {
            obj.insert("source_engine".into(), json!("itdr"));
            obj.insert("fusion_engine".into(), json!(ENGINE_ID));
            obj.insert(
                "evidence".into(),
                json!({
                    "username": username,
                    "ip": ip,
                    "success": success,
                    "mfa_prompted": mfa,
                }),
            );
        }
        out.push(f);
    }
    out
}

pub async fn run_identity_attack_chain_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let params = &ctx.job_params;
    let include_spray = pbool(params, "include_password_spray", true);
    let include_kerberos = pbool(params, "include_kerberos", true);
    let include_itdr = pbool(params, "include_itdr", true);
    let synthesis = pbool(params, "chain_synthesis", true);

    let (spray_r, kerb_r) = tokio::join!(
        async {
            if include_spray {
                crate::password_spray_engine::run_password_spray_result_ctx(target, ctx).await
            } else {
                EngineResult::ok(vec![], "password_spray skipped")
            }
        },
        async {
            if include_kerberos {
                crate::advanced_crypto_engines::run_kerberos_attack_suite_result(target).await
            } else {
                EngineResult::ok(vec![], "kerberos skipped")
            }
        },
    );

    let mut merged = Vec::new();
    let mut sources = Vec::new();
    let mut penalty = 0u32;

    if ingest_source(&mut merged, &mut penalty, "password_spray", &spray_r) {
        sources.push("password_spray");
    }
    if ingest_source(&mut merged, &mut penalty, "kerberos_attack_suite", &kerb_r) {
        sources.push("kerberos_attack_suite");
    }
    if include_itdr {
        let itdr = itdr_findings_from_db(ctx, &host).await;
        if !itdr.is_empty() {
            sources.push("itdr");
            for f in itdr {
                penalty += match severity_rank(finding_severity(&f)) {
                    4 => 12,
                    3 => 7,
                    2 => 3,
                    1 => 1,
                    _ => 0,
                };
                merged.push(f);
            }
        }
    }

    if synthesis {
        let spray_hit = has_signal(&merged, &["spray", "lockout", "credential", "brute"]);
        let kerb_weak = has_signal(&merged, &["kerberos", "as-rep", "kerberoast", "delegation"]);
        let itdr_fail = has_signal(&merged, &["itdr", "failed", "impossible travel", "mfa"]);

        if spray_hit && kerb_weak {
            merged.push(finding(
                ENGINE_ID,
                "Identity chain — spray + Kerberos weakness",
                "critical",
                "T1558",
                "Password spray signals correlate with Kerberos attack surface — likely path to domain compromise.",
                &host,
            ));
            penalty += 20;
        }
        if (spray_hit || kerb_weak) && itdr_fail {
            merged.push(finding(
                ENGINE_ID,
                "Identity chain — credential attack + ITDR anomaly",
                "critical",
                "T1078",
                "Offensive credential signals align with failed/suspicious auth telemetry — prioritize account containment.",
                &host,
            ));
            penalty += 18;
        }
    }

    let grade = (100u32).saturating_sub(penalty.min(95));
    merged.push(finding(
        ENGINE_ID,
        &format!("Identity attack chain grade: {grade}/100"),
        if grade < 40 {
            "critical"
        } else if grade < 60 {
            "high"
        } else if grade < 80 {
            "medium"
        } else {
            "info"
        },
        "T1078",
        &format!(
            "Fused {} source(s): [{}]. Grade reflects correlated identity risk.",
            sources.len(),
            sources.join(", ")
        ),
        &host,
    ));

    if merged.is_empty() {
        return empty_ok(ENGINE_ID, "Identity attack chain: no correlated signals");
    }
    let count = merged.len();
    EngineResult::ok(
        merged,
        format!(
            "Identity attack chain: {count} finding(s) from [{}]",
            sources.join(", ")
        ),
    )
}

pub async fn run_identity_attack_chain(target: &str) {
    print_result(
        run_identity_attack_chain_result(target, &EngineRunContext::default()).await,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_signal_detects_kerberos() {
        let findings = vec![json!({
            "title": "AS-REP roastable account",
            "description": "kerberos pre-auth disabled",
            "severity": "high"
        })];
        assert!(has_signal(&findings, &["kerberos", "as-rep"]));
    }
}
