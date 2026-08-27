//! False-positive / true-positive feedback loop.
//!
//! Drives two effects:
//!   1. **Confidence multiplier** — for each `(tenant, engine, signature_hash)` we
//!      track `fp_count` and `tp_count`. The multiplier returned by
//!      [`confidence_multiplier`] is a number in `[0.1, 1.0]` that callers apply
//!      to `risk_score` so a noisy engine gets discounted in the inbox.
//!   2. **Auto-suppression** — once `fp_count >= 3` for a `(tenant, engine, sig)`
//!      tuple we insert a row in `finding_suppressions`. The persist path checks
//!      this table BEFORE inserting and downgrades the status to `FALSE_POSITIVE`
//!      silently — keeping the audit trail without the noise.
//!
//! Public API:
//!   * [`record_fp`] / [`record_tp`] — called from `api_findings_update_status`
//!   * [`active_suppressions_for_engine`] / [`bump_suppression_hits`] — the persist write path
//!     preloads suppression rules once per `(tenant, engine)` and bumps hit-counts in one batch
//!   * [`confidence_multiplier`] — called from `findings_persist` and the read API

use dashmap::DashMap;
use globset::Glob;
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const AUTO_SUPPRESS_FP_THRESHOLD: i32 = 3;
const SUPPRESSION_CACHE_TTL: Duration = Duration::from_secs(30);

struct CachedRules {
    loaded_at: Instant,
    rules: Vec<SuppressionRule>,
}

static SUPPRESSION_CACHE: LazyLock<DashMap<(i64, String), CachedRules>> =
    LazyLock::new(DashMap::new);
static GLOB_MATCHERS: LazyLock<DashMap<String, Option<globset::GlobMatcher>>> =
    LazyLock::new(DashMap::new);

/// Drop the in-memory glob cache for `(tenant, engine)` after a new rule is written.
pub fn invalidate_suppression_cache(tenant_id: i64, engine: &str) {
    SUPPRESSION_CACHE.remove(&(tenant_id, engine.to_ascii_lowercase()));
}

#[inline]
fn multiplier_from_counts(tp: i32, fp: i32) -> f64 {
    if tp == 0 && fp == 0 {
        return 1.0;
    }
    ((f64::from(tp) + 1.0) / (f64::from(tp) + f64::from(fp) + 1.0)).clamp(0.1, 1.0)
}

/// Record a false-positive vote for a (tenant, engine, signature_hash) combo.
/// Returns `true` if this vote pushed us over the suppression threshold (i.e. a
/// new suppression rule was added).
pub async fn record_fp(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
    target: Option<&str>,
    by_user_id: Option<i64>,
) -> Result<bool, String> {
    if engine.is_empty() || signature_hash.is_empty() {
        return Ok(false);
    }
    let new_fp: i32 = sqlx::query_scalar(
        r#"INSERT INTO engine_confidence_adjustments
                 (tenant_id, engine, signature_hash, tp_count, fp_count, last_seen_at, last_label_at)
           VALUES ($1, $2, $3, 0, 1, now(), now())
           ON CONFLICT (tenant_id, engine, signature_hash) DO UPDATE SET
               fp_count       = engine_confidence_adjustments.fp_count + 1,
               last_seen_at   = now(),
               last_label_at  = now()
           RETURNING fp_count"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("record_fp: {e}"))?;

    if new_fp < AUTO_SUPPRESS_FP_THRESHOLD {
        return Ok(false);
    }
    // Insert a suppression rule if not already present.
    let inserted = sqlx::query(
        r#"INSERT INTO finding_suppressions
                 (tenant_id, engine, signature_hash, target_glob,
                  reason, fp_count_at_create, created_by_user_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())
           ON CONFLICT (tenant_id, engine, signature_hash, COALESCE(target_glob, ''))
           DO NOTHING"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .bind(target)
    .bind(format!("auto:{}_fp_marks", new_fp))
    .bind(new_fp)
    .bind(by_user_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("insert suppression: {e}"))?;
    invalidate_suppression_cache(tenant_id, engine);
    Ok(inserted.rows_affected() > 0)
}

/// Record a true-positive vote (analyst marked FIXED / ACKNOWLEDGED / IN_PROGRESS).
/// Also decays prior `fp_count` by 1 so an engine that fixes its behaviour can
/// climb out of suppression organically.
pub async fn record_tp(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> Result<(), String> {
    if engine.is_empty() || signature_hash.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"INSERT INTO engine_confidence_adjustments
                 (tenant_id, engine, signature_hash, tp_count, fp_count, last_seen_at, last_label_at)
           VALUES ($1, $2, $3, 1, 0, now(), now())
           ON CONFLICT (tenant_id, engine, signature_hash) DO UPDATE SET
               tp_count       = engine_confidence_adjustments.tp_count + 1,
               fp_count       = GREATEST(engine_confidence_adjustments.fp_count - 1, 0),
               last_seen_at   = now(),
               last_label_at  = now()"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("record_tp: {e}"))?;
    Ok(())
}

/// Returns `true` if there's an active suppression matching this finding.
/// Used by the persist path to silently mark new instances as FALSE_POSITIVE.
/// Confidence multiplier in `[0.1, 1.0]` derived from the FP/TP ratio.
///
/// Formula: `(tp + 1) / (tp + fp + 1)` clamped to `[0.1, 1.0]` — a Bayesian
/// shrinkage estimator. With no data the multiplier is 1.0. After 3 FPs the
/// multiplier is ~0.25 (but the finding is also suppressed). After 1 FP and 4
/// TPs the multiplier is ~0.83.
pub async fn confidence_multiplier(
    pool: &PgPool,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> f64 {
    if engine.is_empty() || signature_hash.is_empty() {
        return 1.0;
    }
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return 1.0;
    };
    let row: Option<(i32, i32)> = sqlx::query_as(
        r#"SELECT tp_count, fp_count
             FROM engine_confidence_adjustments
            WHERE tenant_id = $1 AND engine = $2 AND signature_hash = $3"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let (tp, fp) = row.unwrap_or((0, 0));
    if tp == 0 && fp == 0 {
        return 1.0;
    }
    let m = (tp as f64 + 1.0) / (tp as f64 + fp as f64 + 1.0);
    m.clamp(0.1, 1.0)
}

/// Synchronous variant for callers already inside a tenant tx (avoids re-opening).
pub async fn confidence_multiplier_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> f64 {
    if engine.is_empty() || signature_hash.is_empty() {
        return 1.0;
    }
    let row: Option<(i32, i32)> = sqlx::query_as(
        r#"SELECT tp_count, fp_count
             FROM engine_confidence_adjustments
            WHERE tenant_id = $1 AND engine = $2 AND signature_hash = $3"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    let (tp, fp) = row.unwrap_or((0, 0));
    if tp == 0 && fp == 0 {
        return 1.0;
    }
    let m = (tp as f64 + 1.0) / (tp as f64 + fp as f64 + 1.0);
    m.clamp(0.1, 1.0)
}

/// Batch-load confidence multipliers for many `(engine, signature_hash)` pairs in
/// a **single** query. Replaces the per-row `confidence_multiplier` call in the
/// findings read path (which opened one tenant transaction + query per row — an
/// N+1 that cost up to `limit` extra round-trips). Missing pairs default to 1.0.
pub async fn confidence_multipliers_batch(
    pool: &PgPool,
    tenant_id: i64,
    pairs: &[(String, String)],
) -> HashMap<(String, String), f64> {
    let mut out: HashMap<(String, String), f64> = HashMap::new();
    if pairs.is_empty() {
        return out;
    }
    let engines: Vec<String> = pairs.iter().map(|(e, _)| e.clone()).collect();
    let sigs: Vec<String> = pairs.iter().map(|(_, s)| s.clone()).collect();
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return out;
    };
    let rows: Vec<(String, String, i32, i32)> = sqlx::query_as(
        r#"SELECT engine, signature_hash, tp_count, fp_count
             FROM engine_confidence_adjustments
            WHERE tenant_id = $1
              AND engine = ANY($2)
              AND signature_hash = ANY($3)"#,
    )
    .bind(tenant_id)
    .bind(&engines)
    .bind(&sigs)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    for (engine, sig, tp, fp) in rows {
        out.insert((engine, sig), multiplier_from_counts(tp, fp));
    }
    out
}

/// Batch-load the set of **active** suppression signature-hashes for one `(tenant, engine)` in a
/// single query. Replaces the per-finding [`is_suppressed`] call in the persist write path (which
/// opened one tenant transaction + query *per finding* — an N+1 that, on a scan yielding hundreds
/// of findings, cost hundreds of extra round-trips). All findings in a `persist_engine_findings`
/// call share one engine, so we can resolve suppression once. Hit-count telemetry is applied
/// separately via [`bump_suppression_hits`] inside the caller's existing transaction.
pub async fn active_suppressions_for_engine(
    pool: &PgPool,
    tenant_id: i64,
    engine: &str,
) -> Vec<SuppressionRule> {
    if engine.is_empty() {
        return Vec::new();
    }
    let cache_key = (tenant_id, engine.to_ascii_lowercase());
    if let Some(hit) = SUPPRESSION_CACHE.get(&cache_key) {
        if hit.loaded_at.elapsed() < SUPPRESSION_CACHE_TTL {
            return hit.rules.clone();
        }
    }
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Vec::new();
    };
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        r#"SELECT signature_hash, target_glob FROM finding_suppressions
            WHERE tenant_id = $1
              AND engine = $2
              AND (expires_at IS NULL OR expires_at > now())"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    let rules: Vec<SuppressionRule> = rows
        .into_iter()
        .map(|(signature_hash, target_glob)| SuppressionRule {
            signature_hash,
            target_glob,
        })
        .collect();
    SUPPRESSION_CACHE.insert(
        cache_key,
        CachedRules {
            loaded_at: Instant::now(),
            rules: rules.clone(),
        },
    );
    rules
}

/// One active `finding_suppressions` row. `target_glob == None` (or empty) suppresses the
/// signature on ANY target; otherwise the glob must match the finding's target.
#[derive(Debug, Clone)]
pub struct SuppressionRule {
    pub signature_hash: String,
    pub target_glob: Option<String>,
}

/// True when some active rule suppresses `(signature_hash, target_url)`. Respecting `target_glob`
/// is essential: an FP vote on one host must not suppress the same signature on every host.
///
/// Matching uses the same filtered target normalisation as `finding_identity` so an ephemeral
/// source port or query-string session token cannot dodge a 3-FP auto-suppression rule.
#[must_use]
pub fn is_suppressed_by(rules: &[SuppressionRule], signature_hash: &str, target_url: &str) -> bool {
    let target_norm = crate::finding_identity::normalize_target(target_url);
    rules.iter().any(|r| {
        r.signature_hash == signature_hash
            && match r.target_glob.as_deref().map(str::trim) {
                None | Some("") => true,
                Some(glob) => {
                    let glob_norm = crate::finding_identity::normalize_target(glob);
                    glob_matches_fast(glob, target_url)
                        || (!target_norm.is_empty() && glob_matches_fast(glob, &target_norm))
                        || (!glob_norm.is_empty()
                            && !target_norm.is_empty()
                            && glob_matches_fast(&glob_norm, &target_norm))
                }
            }
    })
}

/// In-memory glob match via a process-wide `globset` automaton cache.
/// Exact strings skip the automaton. Invalid patterns fall back to two-pointer.
fn glob_matches_fast(pattern: &str, text: &str) -> bool {
    let pat = pattern.to_ascii_lowercase();
    let txt = text.to_ascii_lowercase();
    if !pat.contains('*') && !pat.contains('?') && !pat.contains('[') {
        return pat == txt;
    }
    let entry = GLOB_MATCHERS
        .entry(pat.clone())
        .or_insert_with(|| Glob::new(&pat).ok().map(|g| g.compile_matcher()));
    match entry.as_ref() {
        Some(m) => m.is_match(&txt),
        None => glob_matches(&pat, &txt),
    }
}

/// Case-insensitive `*`/`?` glob match (standard two-pointer wildcard algorithm). A pattern with
/// no wildcards degenerates to exact equality, matching the common exact-target suppression.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_ti): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Increment `hit_count` / `last_hit_at` for the suppression rules that matched findings this run,
/// in one statement inside the caller's transaction. `signature_hashes` may contain duplicates —
/// each rule is incremented by the number of findings it suppressed, exactly matching the per-row
/// side effect that per-finding [`is_suppressed`] used to perform. No-op on an empty slice.
pub async fn bump_suppression_hits(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hashes: &[String],
) {
    if engine.is_empty() || signature_hashes.is_empty() {
        return;
    }
    let _ = sqlx::query(
        r#"UPDATE finding_suppressions f
              SET hit_count = f.hit_count + c.n, last_hit_at = now()
             FROM (
                 SELECT sig, COUNT(*) AS n
                   FROM unnest($3::text[]) AS sig
                  GROUP BY sig
             ) c
            WHERE f.tenant_id = $1
              AND f.engine = $2
              AND f.signature_hash = c.sig
              AND (f.expires_at IS NULL OR f.expires_at > now())"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hashes)
    .execute(&mut **tx)
    .await;
}

#[cfg(test)]
mod tests {
    use super::{is_suppressed_by, multiplier_from_counts, SuppressionRule};

    fn rule(sig: &str, glob: Option<&str>) -> SuppressionRule {
        SuppressionRule {
            signature_hash: sig.to_string(),
            target_glob: glob.map(str::to_string),
        }
    }

    #[test]
    fn suppression_respects_target_glob_scope() {
        let sig = "abc";
        // NULL glob → suppress on any target.
        let any = [rule(sig, None)];
        assert!(is_suppressed_by(&any, sig, "https://prod.example.com"));

        // Host-scoped glob → only the matching host is suppressed.
        let scoped = [rule(sig, Some("https://staging.example.com"))];
        assert!(is_suppressed_by(
            &scoped,
            sig,
            "https://staging.example.com"
        ));
        assert!(!is_suppressed_by(&scoped, sig, "https://prod.example.com"));

        // Wildcard glob.
        let wild = [rule(sig, Some("https://*.staging.example.com"))];
        assert!(is_suppressed_by(
            &wild,
            sig,
            "https://api.staging.example.com"
        ));
        assert!(!is_suppressed_by(
            &wild,
            sig,
            "https://api.prod.example.com"
        ));

        // Different signature never suppressed regardless of glob.
        assert!(!is_suppressed_by(&any, "other", "https://prod.example.com"));
    }

    #[test]
    fn public_vs_admin_route_templates_do_not_share_suppression() {
        let public = "https://api.corp/api/v1/public/image/6c084089-0aec";
        let admin = "https://api.corp/api/v1/admin/billing/6c084089-0aec";
        let public_key = crate::finding_identity::build_cluster_key(public, "xss", "CWE-79");
        let admin_key = crate::finding_identity::build_cluster_key(admin, "xss", "CWE-79");
        assert_ne!(public_key, admin_key);
        let public_rule = [rule(&public_key, Some(public))];
        assert!(is_suppressed_by(&public_rule, &public_key, public));
        assert!(!is_suppressed_by(&public_rule, &admin_key, admin));
    }

    #[test]
    fn suppression_matches_ephemeral_port_and_query_variants() {
        let sig = "stable-cluster-key";
        // Analyst marked FP against a URL that still carried an OS-allocated port + session.
        let scoped = [rule(
            sig,
            Some("https://app.example.com:54321/login?sid=deadbeef"),
        )];
        assert!(is_suppressed_by(
            &scoped,
            sig,
            "https://app.example.com/login"
        ));
        assert!(is_suppressed_by(
            &scoped,
            sig,
            "https://APP.example.com:49152/login?x=1"
        ));
        assert!(!is_suppressed_by(
            &scoped,
            sig,
            "https://other.example.com/login"
        ));
    }

    #[test]
    fn multiplier_from_counts_matches_formula() {
        assert!((multiplier_from_counts(0, 0) - 1.0).abs() < 1e-6);
        assert!(multiplier_from_counts(0, 3) < 0.5);
        assert!(multiplier_from_counts(0, 100) >= 0.1); // clamped floor
        assert!(multiplier_from_counts(4, 1) > 0.5);
    }

    #[test]
    fn multiplier_neutral_with_no_history() {
        // Pure math test — can't hit DB without a fixture, so we re-derive.
        let m = |tp: f64, fp: f64| ((tp + 1.0) / (tp + fp + 1.0)).clamp(0.1, 1.0);
        assert!((m(0.0, 0.0) - 1.0).abs() < 1e-6);
        assert!(m(0.0, 3.0) < 0.5);
        assert!(m(0.0, 3.0) >= 0.1);
        assert!(m(4.0, 1.0) > 0.5);
    }
}
