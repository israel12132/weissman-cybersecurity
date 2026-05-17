//! Sovereign C2-style coordination (env-governed, safe defaults off):
//! - Tokio `mpsc` fan-out to in-process swarm tasks (telemetry JSON payloads).
//! - Signed command-API port hints on disk for sidecars (HMAC-SHA256); operators still bind the listener (no silent port jump).
//! - Heuristic Cloudflare zone `under_attack` when `security_events` shows many distinct IPs in a window.
//! - Lightweight rotating deception material (Ed25519 SSH-shaped + HS256 JWT + synthetic API key) without per-tick RSA.

use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::Rng;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use sqlx::PgPool;
use ssh_key::{Algorithm as SshAlgorithm, PrivateKey};
use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

static FULL_CLOAK_COOLDOWN_UNTIL: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SovereignSwarmCmd {
    CommandApiPortHint {
        port: u16,
        issued_unix: u64,
        hmac_hex: String,
    },
    HoneytokenRotation {
        trap_id: String,
        jwt_preview: String,
        api_key_preview: String,
        ed25519_public_openssh: String,
    },
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn swarm_hmac_secret() -> Option<Vec<u8>> {
    env::var("WEISSMAN_SOVEREIGN_SWARM_HMAC_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.into_bytes())
        .or_else(|| {
            env::var("WEISSMAN_JWT_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(|s| s.into_bytes())
        })
}

fn sign_port_hint(port: u16, issued_unix: u64, secret: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(format!("{port}:{issued_unix}").as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[derive(Serialize)]
struct DeceptionJwtClaims {
    sub: String,
    iss: String,
    iat: u64,
    exp: u64,
    trap_id: String,
    purpose: String,
}

fn mint_hs256_deception_jwt(trap: &Uuid) -> Result<String, String> {
    let secret = env::var("WEISSMAN_JWT_SECRET")
        .map_err(|_| "WEISSMAN_JWT_SECRET unset".to_string())?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err("WEISSMAN_JWT_SECRET empty".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let claims = DeceptionJwtClaims {
        sub: "weissman-deception".into(),
        iss: "weissman-sovereign-c2".into(),
        iat: now,
        exp: now.saturating_add(3600),
        trap_id: trap.to_string(),
        purpose: "honeytoken_rotation".into(),
    };
    let key = EncodingKey::from_secret(secret.as_bytes());
    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some("JWT".into());
    encode(&header, &claims, &key).map_err(|e| e.to_string())
}

fn generate_ed25519_pub() -> Result<String, String> {
    let key = PrivateKey::random(&mut OsRng, SshAlgorithm::Ed25519).map_err(|e| e.to_string())?;
    key.public_key()
        .to_openssh()
        .map_err(|e| e.to_string())
}

fn spawn_swarm_consumer(
    mut rx: mpsc::Receiver<SovereignSwarmCmd>,
    telemetry: Arc<tokio::sync::broadcast::Sender<String>>,
) {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let payload = serde_json::to_string(&cmd).unwrap_or_else(|_| "{}".to_string());
            tracing::debug!(target: "sovereign_c2", swarm_cmd = %payload);
            let _ = telemetry.send(payload);
        }
    });
}

async fn write_port_hint_atomic(path: &PathBuf, body: &[u8]) -> Result<(), String> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, body)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| e.to_string())
}

async fn cf_set_security_level_under_attack(token: &str, zone_id: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level"
    );
    let body = json!({ "value": "under_attack" });
    let r = client
        .patch(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        let st = r.status();
        let txt = r.text().await.unwrap_or_default();
        return Err(format!("cloudflare security_level: {} {}", st, txt));
    }
    Ok(())
}

fn full_cloak_enabled() -> bool {
    matches!(
        env::var("WEISSMAN_FULL_CLOAK_ENABLE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) && matches!(
        env::var("WEISSMAN_FULL_CLOAK_I_ACKNOWLEDGE_BROAD_IMPACT").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn cf_creds() -> Option<(String, String)> {
    let token = env::var("WEISSMAN_CF_API_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    let zone = env::var("WEISSMAN_CF_ZONE_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    Some((token, zone))
}

async fn maybe_full_cloak(pool: &PgPool) {
    if !full_cloak_enabled() {
        return;
    }
    let Some((token, zone)) = cf_creds() else {
        return;
    };
    let window = env_u64("WEISSMAN_FULL_CLOAK_WINDOW_SECS", 300).max(30);
    let min_ips = env_u64("WEISSMAN_FULL_CLOAK_MIN_DISTINCT_IPS", 8).max(3);
    let cooldown = env_u64("WEISSMAN_FULL_CLOAK_COOLDOWN_SECS", 600).max(60);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now < FULL_CLOAK_COOLDOWN_UNTIL.load(Ordering::Relaxed) {
        return;
    }

    let count: Result<i64, sqlx::Error> = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT client_ip)::bigint
        FROM security_events
        WHERE created_at >= NOW() - ($1 * INTERVAL '1 second')
          AND client_ip IS NOT NULL
        "#,
    )
    .bind(window as i64)
    .fetch_one(pool)
    .await;

    let Ok(n) = count else {
        return;
    };
    if n < min_ips as i64 {
        return;
    }

    match cf_set_security_level_under_attack(&token, &zone).await {
        Ok(()) => {
            info!(
                target: "sovereign_c2",
                "full-cloak: Cloudflare security_level=under_attack (distinct_ips={} window_s={})",
                n,
                window
            );
            FULL_CLOAK_COOLDOWN_UNTIL.store(now.saturating_add(cooldown), Ordering::Relaxed);
        }
        Err(e) => warn!(target: "sovereign_c2", "full-cloak failed: {}", e),
    }
}

fn honeytoken_bundle() -> Option<SovereignSwarmCmd> {
    let trap = Uuid::new_v4();
    let jwt = mint_hs256_deception_jwt(&trap).unwrap_or_default();
    let jwt_preview = jwt.chars().take(48).collect::<String>();
    let api_key = format!(
        "wm_sk_{}",
        hex::encode(rand::thread_rng().gen::<[u8; 24]>())
    );
    let api_key_preview = format!("{}…", &api_key[..api_key.len().min(12)]);
    let pub_ssh = generate_ed25519_pub().unwrap_or_default();
    Some(SovereignSwarmCmd::HoneytokenRotation {
        trap_id: trap.to_string(),
        jwt_preview,
        api_key_preview,
        ed25519_public_openssh: pub_ssh,
    })
}

/// Starts optional sovereign background loops (port hints, honeytoken rotation, security-event triage).
pub fn spawn_sovereign_stack(
    app_pool: Arc<PgPool>,
    telemetry: Arc<tokio::sync::broadcast::Sender<String>>,
    swarm_rx: Option<mpsc::Receiver<SovereignSwarmCmd>>,
    swarm_tx: Option<Arc<mpsc::Sender<SovereignSwarmCmd>>>,
) {
    if let Some(rx) = swarm_rx {
        spawn_swarm_consumer(rx, telemetry.clone());
    }

    let hop_secs = env_u64("WEISSMAN_SOVEREIGN_PORT_HOP_INTERVAL_SECS", 0);
    let hint_path = env::var("WEISSMAN_SOVEREIGN_PORT_HINT_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    if hop_secs > 0 {
        match (&hint_path, swarm_hmac_secret()) {
            (None, _) => {
                warn!(target: "sovereign_c2", "port hop interval set but WEISSMAN_SOVEREIGN_PORT_HINT_PATH unset; skipping port hints");
            }
            (Some(_), None) => {
                warn!(target: "sovereign_c2", "port hop enabled but no WEISSMAN_SOVEREIGN_SWARM_HMAC_SECRET / WEISSMAN_JWT_SECRET; skipping");
            }
            (Some(path), Some(secret)) => {
                let path = path.clone();
                let tx = swarm_tx.clone();
                let secret = Arc::new(secret);
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(Duration::from_secs(hop_secs.max(10)));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        let min_p = env_u64("WEISSMAN_SOVEREIGN_PORT_MIN", 40000).max(1024) as u16;
                        let max_p =
                            env_u64("WEISSMAN_SOVEREIGN_PORT_MAX", 41000).max(u64::from(min_p)) as u16;
                        let port = rand::thread_rng().gen_range(min_p..=max_p);
                        let issued = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let hmac_hex = match sign_port_hint(port, issued, &secret) {
                            Ok(h) => h,
                            Err(e) => {
                                warn!(target: "sovereign_c2", "port hint hmac: {}", e);
                                continue;
                            }
                        };
                        let file_json = json!({
                            "port": port,
                            "issued_unix": issued,
                            "hmac_hex": hmac_hex,
                        });
                        let bytes =
                            serde_json::to_vec(&file_json).unwrap_or_else(|_| b"{}".to_vec());
                        if let Err(e) = write_port_hint_atomic(&path, &bytes).await {
                            warn!(target: "sovereign_c2", "port hint write: {}", e);
                        }
                        if let Some(t) = &tx {
                            let cmd = SovereignSwarmCmd::CommandApiPortHint {
                                port,
                                issued_unix: issued,
                                hmac_hex: hmac_hex.clone(),
                            };
                            let _ = t.try_send(cmd);
                        }
                    }
                });
            }
        }
    }

    let honey_secs = env_u64("WEISSMAN_SOVEREIGN_HONEYTOKEN_INTERVAL_SECS", 0);
    if honey_secs > 0 {
        if let Some(tx) = swarm_tx.clone() {
            let min_gap = Duration::from_secs(honey_secs.max(60));
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(min_gap);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    if let Some(cmd) = honeytoken_bundle() {
                        let _ = tx.try_send(cmd);
                    }
                }
            });
        } else {
            warn!(target: "sovereign_c2", "WEISSMAN_SOVEREIGN_HONEYTOKEN_INTERVAL_SECS set but mpsc disabled; enable WEISSMAN_SOVEREIGN_MPSC_CAPACITY");
        }
    }

    let poll_secs = env_u64("WEISSMAN_FULL_CLOAK_POLL_SECS", 60).max(15);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(poll_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            maybe_full_cloak(&app_pool).await;
        }
    });
}
