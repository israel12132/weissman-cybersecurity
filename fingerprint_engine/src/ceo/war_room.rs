//! Persisted war-room phases + SSE fan-out from DB polling (works across separate worker processes).

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;
use uuid::Uuid;

/// Mirror orchestrator telemetry into `ceo_war_room_events` so CEO SSE shows live lines for async jobs (e.g. `tenant_full_scan`).
#[derive(Clone)]
pub struct WarRoomMirror {
    pub pool: Arc<PgPool>,
    pub tenant_id: i64,
    pub job_id: Uuid,
}

impl WarRoomMirror {
    pub fn emit(&self, phase: &str, severity: &str, payload: Value) {
        let pool = self.pool.clone();
        let tid = self.tenant_id;
        let jid = self.job_id;
        let phase = phase.to_string();
        let severity = severity.to_string();
        tokio::spawn(async move {
            if let Err(e) = insert_war_room_event(
                pool.as_ref(),
                tid,
                &jid.to_string(),
                Some(jid),
                &phase,
                &severity,
                &payload,
            )
            .await
            {
                warn!(target: "ceo_war_room", error = %e, "war room mirror insert failed");
            }
        });
    }
}

/// Correlates council_synthesis events to one async job / UI session.
#[derive(Clone, Debug)]
pub struct WarRoomContext {
    pub pool: std::sync::Arc<PgPool>,
    pub tenant_id: i64,
    pub session_id: String,
    pub async_job_id: Option<Uuid>,
}

impl WarRoomContext {
    pub async fn emit(&self, phase: &str, severity: &str, payload: &Value) {
        if let Err(e) = insert_war_room_event(
            self.pool.as_ref(),
            self.tenant_id,
            self.session_id.as_str(),
            self.async_job_id,
            phase,
            severity,
            payload,
        )
        .await
        {
            warn!(target: "ceo_war_room", error = %e, "insert_war_room_event failed");
        }
    }
}

pub async fn insert_war_room_event(
    pool: &PgPool,
    tenant_id: i64,
    session_id: &str,
    async_job_id: Option<Uuid>,
    phase: &str,
    severity: &str,
    payload: &Value,
) -> Result<i64, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO ceo_war_room_events (tenant_id, session_id, async_job_id, phase, severity, payload)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(async_job_id)
    .bind(phase)
    .bind(severity)
    .bind(payload)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// SSE: poll new rows for tenant (and optional session filter).
pub fn sse_war_room_stream(
    pool: std::sync::Arc<PgPool>,
    tenant_id: i64,
    mut since_id: i64,
    session_filter: Option<String>,
) -> impl futures::Stream<Item = Result<axum::response::sse::Event, Infallible>> {
    let filter_for_hello = session_filter.clone();
    async_stream::stream! {
        let hello = json!({
            "type": "connected",
            "filter": filter_for_hello,
            "message": "War room SSE active — streaming rows from ceo_war_room_events for this job/session id",
        });
        if let Ok(s) = serde_json::to_string(&hello) {
            yield Ok(axum::response::sse::Event::default().event("connected").data(s));
        }
        let mut first_tick = true;
        loop {
            if !first_tick {
                tokio::time::sleep(Duration::from_millis(750)).await;
            }
            first_tick = false;
            let rows = match fetch_events_since(pool.as_ref(), tenant_id, since_id, session_filter.as_deref()).await {
                Ok(r) => r,
                Err(e) => {
                    let err = json!({ "type": "error", "message": e.to_string() });
                    yield Ok(axum::response::sse::Event::default().event("error").data(err.to_string()));
                    continue;
                }
            };
            for (id, ev) in rows {
                since_id = since_id.max(id);
                if let Ok(s) = serde_json::to_string(&ev) {
                    yield Ok(axum::response::sse::Event::default().event("war_room").data(s));
                }
            }
        }
    }
}

async fn fetch_events_since(
    pool: &PgPool,
    tenant_id: i64,
    since_id: i64,
    session: Option<&str>,
) -> Result<Vec<(i64, Value)>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = if let Some(sid) = session.filter(|s| !s.is_empty()) {
        sqlx::query(
            r#"SELECT id, session_id, async_job_id, phase, severity, payload,
                      to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
               FROM ceo_war_room_events
               WHERE id > $1
                 AND (session_id = $2 OR async_job_id::text = $2)
               ORDER BY id ASC LIMIT 64"#,
        )
        .bind(since_id)
        .bind(sid)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(
            r#"SELECT id, session_id, async_job_id, phase, severity, payload,
                      to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
               FROM ceo_war_room_events
               WHERE id > $1
               ORDER BY id ASC LIMIT 64"#,
        )
        .bind(since_id)
        .fetch_all(&mut *tx)
        .await?
    };
    let _ = tx.commit().await;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: i64 = r.try_get("id")?;
        let ev = json!({
            "id": id,
            "session_id": r.try_get::<String, _>("session_id").unwrap_or_default(),
            "async_job_id": r.try_get::<Option<Uuid>, _>("async_job_id").ok().flatten(),
            "phase": r.try_get::<String, _>("phase").unwrap_or_default(),
            "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
            "payload": r.try_get::<Value, _>("payload").unwrap_or(json!({})),
            "ts": r.try_get::<String, _>("ts").unwrap_or_default(),
        });
        out.push((id, ev));
    }
    Ok(out)
}
