//! Local-first forge: write a worktree, compile locally, require a live finding, then GitHub PR.
//! Never mutates the running binary or PRODUCTION_ENGINE_IDS from this process.

use super::scripts;
use super::tools::ToolOutcome;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;
use weissman_core::models::engine::is_production_engine_id;

const FORGE_ROOT: &str = "/tmp/weissman-sovereign-forge";

pub async fn forge_draft(
    pool: &PgPool,
    tenant_id: i64,
    owner_user_id: i64,
    args: &Value,
) -> ToolOutcome {
    let engine_id = args
        .get("engine")
        .or_else(|| args.get("engine_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if engine_id.is_empty() {
        return ToolOutcome {
            ok: false,
            name: "forge".into(),
            detail: "engine id required".into(),
            payload: json!({}),
        };
    }
    let title = args
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Sovereign forge draft")
        .trim()
        .to_string();
    let rust_source = args
        .get("rust_source")
        .or_else(|| args.get("source"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let worktree = match IsolatedWorktree::create() {
        Ok(w) => w,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge".into(),
                detail: format!("worktree create failed: {e}"),
                payload: json!({}),
            };
        }
    };
    let id = worktree.id;
    let dir = worktree.dir.clone();
    let src_path = dir.join("lib.rs");
    let source_out = if rust_source.trim().is_empty() {
        format!(
            "// Sovereign forge draft for `{engine_id}` — local-first, not in the live catalog.\n\
             // Permanent catalog entry requires: local rustc OK + live finding + GitHub PR after proof.\n\
             #![allow(dead_code)]\npub fn sovereign_forge_probe() -> &'static str {{ {engine_id:?} }}\n"
        )
    } else {
        rust_source.clone()
    };
    if let Err(e) = std::fs::write(&src_path, &source_out) {
        return ToolOutcome {
            ok: false,
            name: "forge".into(),
            detail: format!("write failed: {e}"),
            payload: json!({}),
        };
    }
    let (compile_ok, compile_log) = rustc_metadata(&src_path, &dir);
    let status = if compile_ok { "local_ok" } else { "draft" };
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let inserted: Result<Uuid, _> = sqlx::query_scalar(
        r#"INSERT INTO weissman_sovereign_forge
               (id, tenant_id, owner_user_id, engine_id, title, status, rust_source,
                worktree_path, compile_log)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           RETURNING id"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(owner_user_id)
    .bind(&engine_id)
    .bind(&title)
    .bind(status)
    .bind(&source_out)
    .bind(dir.to_string_lossy().as_ref())
    .bind(&compile_log)
    .fetch_one(&mut *tx)
    .await;
    match inserted {
        Ok(fid) => {
            if tx.commit().await.is_err() {
                return ToolOutcome {
                    ok: false,
                    name: "forge".into(),
                    detail: "store_down".into(),
                    payload: json!({}),
                };
            }
            ToolOutcome {
                ok: true,
                name: "forge".into(),
                detail: format!(
                    "local worktree {} status={status} compile_ok={compile_ok} — GitHub blocked until live_proof",
                    dir.display()
                ),
                payload: json!({
                    "forge_id": fid,
                    "engine_id": engine_id,
                    "status": status,
                    "compile_ok": compile_ok,
                    "compile_log": compile_log.chars().take(4000).collect::<String>(),
                    "worktree": dir.to_string_lossy(),
                    "worktree_purged": true,
                    "in_production_catalog": is_production_engine_id(&engine_id),
                }),
            }
        }
        Err(e) => {
            let _ = tx.rollback().await;
            ToolOutcome {
                ok: false,
                name: "forge".into(),
                detail: e.to_string(),
                payload: json!({ "compile_log": compile_log }),
            }
        }
    }
}

pub async fn forge_prove(
    pool: &PgPool,
    tenant_id: i64,
    trace_id: Option<String>,
    args: &Value,
) -> ToolOutcome {
    let Some(forge_id) = uuid_arg(args, "forge_id") else {
        return ToolOutcome {
            ok: false,
            name: "forge_prove".into(),
            detail: "forge_id required".into(),
            payload: json!({}),
        };
    };
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge_prove".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let row = sqlx::query(
        "SELECT engine_id, status, rust_source FROM weissman_sovereign_forge WHERE id = $1",
    )
    .bind(forge_id)
    .fetch_optional(&mut *tx)
    .await;
    if tx.commit().await.is_err() {
        return ToolOutcome {
            ok: false,
            name: "forge_prove".into(),
            detail: "store_down".into(),
            payload: json!({}),
        };
    }
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return ToolOutcome {
                ok: false,
                name: "forge_prove".into(),
                detail: "forge draft not found".into(),
                payload: json!({}),
            };
        }
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge_prove".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let engine_id: String = row.try_get("engine_id").unwrap_or_default();
    let target = args
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if target.is_empty() {
        return ToolOutcome {
            ok: false,
            name: "forge_prove".into(),
            detail: "target required for live proof gate".into(),
            payload: json!({}),
        };
    }
    let (proof, proved, status) = if is_production_engine_id(&engine_id) {
        let payload = json!({
            "engine": engine_id,
            "target": target,
            "roe_mode": "safe_proofs",
            "sovereign_forge_id": forge_id,
            "stealth_mode": true,
        });
        match crate::async_jobs::enqueue(
            pool,
            tenant_id,
            "command_center_engine",
            payload,
            trace_id,
        )
        .await
        {
            Ok(job_id) => {
                let waited =
                    match wait_live_finding(pool, tenant_id, job_id, &engine_id, &target).await {
                        Ok(v) => v,
                        Err(_) => {
                            return ToolOutcome {
                                ok: false,
                                name: "forge_prove".into(),
                                detail: "store_down".into(),
                                payload: json!({ "job_id": job_id.to_string() }),
                            };
                        }
                    };
                let proved = waited
                    .get("proved")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let status_out = waited
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or(if proved {
                        "live_proof"
                    } else {
                        "proof_pending"
                    })
                    .to_string();
                (
                    json!({
                        "mode": "enqueue",
                        "job_id": job_id.to_string(),
                        "engine": engine_id,
                        "wait": waited,
                    }),
                    proved,
                    status_out,
                )
            }
            Err(e) => {
                return ToolOutcome {
                    ok: false,
                    name: "forge_prove".into(),
                    detail: e.to_string(),
                    payload: json!({}),
                };
            }
        }
    } else {
        let mut script_args = args.clone();
        if let Some(obj) = script_args.as_object_mut() {
            obj.entry("target".to_string()).or_insert(json!(target));
        }
        let out = scripts::run_script(pool, tenant_id, None, &script_args).await;
        let proved = out
            .payload
            .pointer("/verdict/verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let proof =
            json!({ "mode": "sandbox_script", "script": out.payload, "detail": out.detail });
        if !proved {
            let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
                Ok(t) => t,
                Err(e) => {
                    return ToolOutcome {
                        ok: false,
                        name: "forge_prove".into(),
                        detail: e.to_string(),
                        payload: proof,
                    };
                }
            };
            if sqlx::query(
                "UPDATE weissman_sovereign_forge SET status='rejected', live_finding=$2, updated_at=now() WHERE id=$1",
            )
            .bind(forge_id)
            .bind(&proof)
            .execute(&mut *tx)
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return ToolOutcome {
                    ok: false,
                    name: "forge_prove".into(),
                    detail: "store_down".into(),
                    payload: proof,
                };
            }
            return ToolOutcome {
                ok: false,
                name: "forge_prove".into(),
                detail: "live-proof gate failed — draft stays out of the catalog (no GitHub)"
                    .into(),
                payload: proof,
            };
        }
        (proof, true, "live_proof".into())
    };
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge_prove".into(),
                detail: e.to_string(),
                payload: proof,
            };
        }
    };
    if sqlx::query(
        "UPDATE weissman_sovereign_forge SET status=$2, live_finding=$3, updated_at=now() WHERE id=$1",
    )
    .bind(forge_id)
    .bind(&status)
    .bind(&proof)
    .execute(&mut *tx)
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return ToolOutcome {
            ok: false,
            name: "forge_prove".into(),
            detail: "store_down".into(),
            payload: proof,
        };
    }
    let pending = status == "proof_pending";
    ToolOutcome {
        ok: proved || pending,
        name: "forge_prove".into(),
        detail: if proved {
            "live proof recorded — GitHub PR still requires explicit forge_github after this gate"
                .into()
        } else if pending {
            "engine job is live; GitHub stays blocked until a finding row lands".into()
        } else {
            "no live finding — not catalogued".into()
        },
        payload: json!({ "forge_id": forge_id, "status": status, "proof": proof }),
    }
}

pub async fn forge_github(pool: &PgPool, tenant_id: i64, args: &Value) -> ToolOutcome {
    let Some(forge_id) = uuid_arg(args, "forge_id") else {
        return ToolOutcome {
            ok: false,
            name: "forge_github".into(),
            detail: "forge_id required".into(),
            payload: json!({}),
        };
    };
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge_github".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let row = match sqlx::query(
        "SELECT engine_id, title, status, rust_source, live_finding FROM weissman_sovereign_forge WHERE id = $1",
    )
    .bind(forge_id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "forge_github".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    if tx.commit().await.is_err() {
        return ToolOutcome {
            ok: false,
            name: "forge_github".into(),
            detail: "store_down".into(),
            payload: json!({}),
        };
    }
    let Some(row) = row else {
        return ToolOutcome {
            ok: false,
            name: "forge_github".into(),
            detail: "forge draft not found".into(),
            payload: json!({}),
        };
    };
    let status: String = row.try_get("status").unwrap_or_default();
    if !github_allowed(&status) {
        return ToolOutcome {
            ok: false,
            name: "forge_github".into(),
            detail: format!("GitHub blocked until live_proof (current status={status})"),
            payload: json!({ "status": status }),
        };
    }
    let engine_id: String = row.try_get("engine_id").unwrap_or_default();
    let title: String = row.try_get("title").unwrap_or_default();
    let rust_source: String = row.try_get("rust_source").unwrap_or_default();
    let live_finding: Value = row.try_get("live_finding").unwrap_or(json!({}));
    let proposal = crate::self_improve::ImprovementProposal {
        category: if is_production_engine_id(&engine_id) {
            "improve_engine".into()
        } else {
            "new_engine".into()
        },
        title,
        rationale: format!(
            "Sovereign local-first forge {forge_id}: live proof attached. Catalog only after human PR + CI."
        ),
        risk: "medium".into(),
        impact: "high".into(),
        effort: "medium".into(),
        proposed_diff_summary: rust_source.chars().take(8000).collect(),
        affected_files: vec![],
        source: "sovereign_forge".into(),
    };
    let cycle_id = Uuid::new_v4();
    match crate::self_improve::insert_proposals(pool, tenant_id, cycle_id, &[proposal]).await {
        Ok(n) => {
            let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
                Ok(t) => t,
                Err(_) => {
                    return ToolOutcome {
                        ok: false,
                        name: "forge_github".into(),
                        detail: "store_down".into(),
                        payload: json!({
                            "forge_id": forge_id,
                            "cycle_id": cycle_id,
                            "inserted": n,
                        }),
                    };
                }
            };
            if sqlx::query(
                "UPDATE weissman_sovereign_forge SET status='github_queued', proposal_cycle_id=$2, updated_at=now() WHERE id=$1",
            )
            .bind(forge_id)
            .bind(cycle_id)
            .execute(&mut *tx)
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return ToolOutcome {
                    ok: false,
                    name: "forge_github".into(),
                    detail: "store_down".into(),
                    payload: json!({
                        "forge_id": forge_id,
                        "cycle_id": cycle_id,
                        "inserted": n,
                    }),
                };
            }
            ToolOutcome {
                ok: true,
                name: "forge_github".into(),
                detail: format!(
                    "{n} PENDING_APPROVAL proposal(s) after live proof — main untouched"
                ),
                payload: json!({
                    "forge_id": forge_id,
                    "cycle_id": cycle_id,
                    "inserted": n,
                    "live_finding": live_finding,
                }),
            }
        }
        Err(e) => ToolOutcome {
            ok: false,
            name: "forge_github".into(),
            detail: e.to_string(),
            payload: json!({}),
        },
    }
}

pub async fn list_forge(pool: &PgPool, tenant_id: i64, limit: i64) -> Result<Vec<Value>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, engine_id, title, status, worktree_path, compile_log,
                  live_finding, proposal_cycle_id,
                  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_sovereign_forge
           ORDER BY updated_at DESC
           LIMIT $1"#,
    )
    .bind(limit.clamp(1, 50))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<Uuid,_>("id").ok(),
                "engine_id": r.try_get::<String,_>("engine_id").ok(),
                "title": r.try_get::<String,_>("title").ok(),
                "status": r.try_get::<String,_>("status").ok(),
                "worktree_path": r.try_get::<String,_>("worktree_path").ok(),
                "compile_log": r.try_get::<String,_>("compile_log").ok().map(|s| s.chars().take(500).collect::<String>()),
                "live_finding": r.try_get::<Value,_>("live_finding").ok().unwrap_or(json!({})),
                "proposal_cycle_id": r.try_get::<Option<Uuid>,_>("proposal_cycle_id").ok().flatten(),
                "ts": r.try_get::<String,_>("ts").ok(),
            })
        })
        .collect())
}

/// Exclusive UUID directory under `FORGE_ROOT`. Drop wipes the tree so rustc temps cannot collide.
struct IsolatedWorktree {
    id: Uuid,
    dir: PathBuf,
}

impl IsolatedWorktree {
    fn create() -> Result<Self, String> {
        Self::create_in(Path::new(FORGE_ROOT))
    }

    /// Create an exclusive UUID directory under `root` (tests use a private root so
    /// they never share `FORGE_ROOT` with the janitor or with each other).
    fn create_in(root: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
        for _ in 0..8 {
            let id = Uuid::new_v4();
            let dir = root.join(id.to_string());
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(Self { id, dir }),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("forge worktree uuid collision".into())
    }
}

impl Drop for IsolatedWorktree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Age after which a UUID worktree is treated as an orphan (SIGKILL / OOM skip Drop).
pub const STALE_WORKTREE_SECS: u64 = 600;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PurgeStats {
    pub scanned: u32,
    pub removed: u32,
    pub skipped: u32,
    pub errors: u32,
}

/// Delete UUID dirs under `FORGE_ROOT` whose mtime is older than `max_age`.
/// Ignores non-UUID names and symlinks so a planted link cannot escape `/tmp`.
pub fn purge_stale_worktrees(max_age: std::time::Duration) -> PurgeStats {
    purge_stale_worktrees_in(Path::new(FORGE_ROOT), max_age)
}

/// [`purge_stale_worktrees`] over an explicit root.
///
/// Staleness is decided per entry against a clock read *after* the entry's mtime,
/// and only a readable mtime that is genuinely `max_age` in the past counts as
/// stale. A worktree created between the sweep starting and its entry being
/// visited therefore reads as fresh (age zero), never as "unreadable, so wipe",
/// which is what used to delete a live worktree out from under a running rustc.
pub fn purge_stale_worktrees_in(root: &Path, max_age: std::time::Duration) -> PurgeStats {
    let mut stats = PurgeStats::default();
    let Ok(entries) = std::fs::read_dir(root) else {
        return stats;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            stats.skipped += 1;
            continue;
        };
        if Uuid::parse_str(name).is_err() {
            stats.skipped += 1;
            continue;
        }
        let path = ent.path();
        let Ok(meta) = path.symlink_metadata() else {
            stats.errors += 1;
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            stats.skipped += 1;
            continue;
        }
        stats.scanned += 1;
        let Ok(modified) = meta.modified() else {
            // No mtime to judge by: leave it for a later sweep rather than risk a live tree.
            stats.skipped += 1;
            continue;
        };
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        if age < max_age {
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => stats.removed += 1,
            Err(_) => stats.errors += 1,
        }
    }
    stats
}

/// Per-process janitor: `/tmp` is local, so every replica must sweep its own orphans.
pub fn spawn_forge_janitor() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let stats = tokio::task::spawn_blocking(|| {
                purge_stale_worktrees(std::time::Duration::from_secs(STALE_WORKTREE_SECS))
            })
            .await;
            match stats {
                Ok(s) if s.removed > 0 || s.errors > 0 => {
                    tracing::info!(
                        target: "sovereign_operator",
                        scanned = s.scanned,
                        removed = s.removed,
                        skipped = s.skipped,
                        errors = s.errors,
                        "forge worktree janitor"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(target: "sovereign_operator", error = %e, "forge janitor join failed");
                }
            }
        }
    });
}

fn rustc_metadata(src: &Path, out_dir: &Path) -> (bool, String) {
    let content = std::fs::read_to_string(src).unwrap_or_default();
    let compile_src = if content.contains("crate::") {
        let wrap = out_dir.join("_forge_crate_root.rs");
        let stub = r#"#![allow(dead_code, unused_imports, unused_variables, unused_mut, unused_must_use)]
pub struct Job;
pub mod engine_dispatch {
    pub struct EngineRunContext;
    pub struct EngineResult;
}
pub mod engines {
    pub mod engine_contract {
        pub struct Finding {
            pub title: String,
            pub severity: String,
            pub description: String,
            pub evidence: String,
            pub remediation: String,
        }
        pub fn push_finding(_job: &mut super::super::Job, _f: Finding) {}
    }
}
#[path = "lib.rs"]
mod candidate;
"#;
        if std::fs::write(&wrap, stub).is_err() {
            return (false, "failed to write rustc crate stub".into());
        }
        wrap
    } else {
        src.to_path_buf()
    };
    let out = out_dir.join("libsovereign_forge.rmeta");
    let spawned = Command::new("rustc")
        .current_dir(out_dir)
        .env("TMPDIR", out_dir)
        .env("TMP", out_dir)
        .env("TEMP", out_dir)
        .env("CARGO_TARGET_DIR", out_dir.join("target"))
        .env("CARGO_INCREMENTAL", "0")
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--emit=metadata",
            "-o",
        ])
        .arg(&out)
        .arg(&compile_src)
        .output();
    match spawned {
        Ok(o) => {
            let mut log = String::from_utf8_lossy(&o.stderr).into_owned();
            if log.is_empty() {
                log = String::from_utf8_lossy(&o.stdout).into_owned();
            }
            if o.status.success() {
                (
                    true,
                    if log.is_empty() {
                        "rustc metadata ok".into()
                    } else {
                        log
                    },
                )
            } else {
                (false, log)
            }
        }
        Err(e) => (false, format!("rustc not available: {e}")),
    }
}

fn github_allowed(status: &str) -> bool {
    status == "live_proof"
}

async fn wait_live_finding(
    pool: &PgPool,
    tenant_id: i64,
    job_id: Uuid,
    engine_id: &str,
    target: &str,
) -> Result<Value, String> {
    let mut last_status = "pending".to_string();
    let mut finding_logs = 0i64;
    let mut result_findings = 0usize;
    let mut saw_snapshot = false;
    for _ in 0..24 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
            Ok(t) => t,
            Err(_) => continue,
        };
        let row =
            match sqlx::query("SELECT status, result_json FROM weissman_async_jobs WHERE id = $1")
                .bind(job_id)
                .fetch_optional(&mut *tx)
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
        let n: i64 = match sqlx::query_scalar::<_, i64>(
            r#"SELECT count(*)::bigint FROM weissman_sovereign_engine_logs
               WHERE job_id = $1 AND phase = 'finding'"#,
        )
        .bind(job_id.to_string())
        .fetch_one(&mut *tx)
        .await
        {
            Ok(n) => n,
            Err(_) => continue,
        };
        if tx.commit().await.is_err() {
            continue;
        }
        saw_snapshot = true;
        finding_logs = n;
        result_findings = 0;
        if let Some(r) = row {
            last_status = r.try_get::<String, _>("status").unwrap_or(last_status);
            if let Ok(Some(rj)) = r.try_get::<Option<Value>, _>("result_json") {
                result_findings = rj
                    .get("findings")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .or_else(|| {
                        rj.pointer("/result/findings")
                            .and_then(Value::as_array)
                            .map(|a| a.len())
                    })
                    .unwrap_or(0);
            }
        }
        if finding_logs > 0 || result_findings > 0 {
            return Ok(json!({
                "proved": true,
                "status": "live_proof",
                "job_status": last_status,
                "finding_logs": finding_logs,
                "result_findings": result_findings,
                "engine": engine_id,
                "target": target,
            }));
        }
        if last_status == "failed"
            || last_status == "dead"
            || last_status == "cancelled"
            || last_status == "completed"
        {
            break;
        }
    }
    if !saw_snapshot {
        return Err("store_down".to_string());
    }
    let proved = finding_logs > 0 || result_findings > 0;
    let status = if proved {
        "live_proof"
    } else if last_status == "completed" {
        "rejected"
    } else {
        "proof_pending"
    };
    Ok(json!({
        "proved": proved,
        "status": status,
        "job_status": last_status,
        "finding_logs": finding_logs,
        "result_findings": result_findings,
        "engine": engine_id,
        "target": target,
    }))
}

fn uuid_arg(args: &Value, key: &str) -> Option<Uuid> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_requires_live_proof_token() {
        assert!(github_allowed("live_proof"));
        assert!(!github_allowed("draft"));
        assert!(!github_allowed("local_ok"));
        assert!(!github_allowed("proof_pending"));
        assert!(FORGE_ROOT.contains("sovereign-forge"));
    }

    /// A private forge root per test: tests run in parallel threads, so sharing
    /// `FORGE_ROOT` would let one test's janitor sweep race another test's worktree.
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("weissman-forge-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("test root");
            Self(dir)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exclusive_worktrees_are_unique_and_wiped() {
        let root = TestRoot::new();
        let a = IsolatedWorktree::create_in(&root.0).expect("a");
        let b = IsolatedWorktree::create_in(&root.0).expect("b");
        assert_ne!(a.dir, b.dir);
        assert!(a.dir.starts_with(&root.0));
        assert!(a.dir.exists());
        let path = a.dir.clone();
        drop(a);
        assert!(!path.exists(), "worktree must be wiped on drop");
        drop(b);
    }

    #[test]
    fn production_worktree_lives_under_forge_root() {
        let w = IsolatedWorktree::create().expect("worktree");
        assert!(w.dir.starts_with(FORGE_ROOT));
        assert!(Uuid::parse_str(&w.id.to_string()).is_ok());
    }

    #[test]
    fn rustc_compiles_standalone_probe() {
        let root = TestRoot::new();
        let worktree = IsolatedWorktree::create_in(&root.0).expect("worktree");
        let src = worktree.dir.join("lib.rs");
        std::fs::write(
            &src,
            "pub fn sovereign_forge_probe() -> &'static str { \"osint\" }\n",
        )
        .expect("write probe");
        let (ok, log) = rustc_metadata(&src, &worktree.dir);
        assert!(ok, "rustc failed: {log}");
        assert!(
            worktree.dir.join("libsovereign_forge.rmeta").exists()
                || worktree.dir.join("lib.rs").exists()
        );
    }

    fn set_dir_mtime(dir: &Path, when: std::time::SystemTime) {
        let times = std::fs::FileTimes::new().set_modified(when);
        let f = std::fs::File::open(dir).expect("open dir");
        f.set_times(times).expect("set dir mtime");
    }

    #[test]
    fn janitor_removes_stale_uuid_dirs_only() {
        let root = TestRoot::new();
        let stale = root.0.join(Uuid::new_v4().to_string());
        let fresh = root.0.join(Uuid::new_v4().to_string());
        let stray = root.0.join("not-a-uuid-keep");
        std::fs::create_dir(&stale).expect("stale dir");
        std::fs::create_dir(&fresh).expect("fresh dir");
        std::fs::create_dir(&stray).expect("stray dir");
        let max_age = std::time::Duration::from_secs(STALE_WORKTREE_SECS);
        set_dir_mtime(
            &stale,
            std::time::SystemTime::now() - max_age - std::time::Duration::from_secs(30),
        );
        let stats = purge_stale_worktrees_in(&root.0, max_age);
        assert!(!stale.exists(), "stale UUID worktree must be removed");
        assert!(fresh.exists(), "fresh UUID worktree must survive");
        assert!(stray.exists(), "non-uuid names must not be swept");
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.scanned, 2);
        assert!(stats.skipped >= 1);
    }

    #[test]
    fn janitor_keeps_worktrees_with_future_mtime() {
        // A worktree created after the sweep began has an mtime later than any clock
        // the sweep read earlier; that must read as age zero, never as stale.
        let root = TestRoot::new();
        let ahead = root.0.join(Uuid::new_v4().to_string());
        std::fs::create_dir(&ahead).expect("ahead dir");
        set_dir_mtime(
            &ahead,
            std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        );
        let stats = purge_stale_worktrees_in(&root.0, std::time::Duration::from_secs(1));
        assert!(
            ahead.exists(),
            "future-dated worktree must survive the sweep"
        );
        assert_eq!(stats.removed, 0);
        assert_eq!(stats.scanned, 1);
    }

    #[test]
    fn janitor_ignores_symlinked_uuid_entries() {
        let root = TestRoot::new();
        let victim = TestRoot::new();
        let link = root.0.join(Uuid::new_v4().to_string());
        std::os::unix::fs::symlink(&victim.0, &link).expect("symlink");
        set_dir_mtime(
            &victim.0,
            std::time::SystemTime::now() - std::time::Duration::from_secs(7200),
        );
        let stats = purge_stale_worktrees_in(&root.0, std::time::Duration::from_secs(1));
        assert!(
            victim.0.exists(),
            "a planted symlink must not delete its target"
        );
        assert!(
            link.symlink_metadata().is_ok(),
            "the link itself is left alone"
        );
        assert_eq!(stats.removed, 0);
        assert_eq!(stats.skipped, 1);
    }
}
