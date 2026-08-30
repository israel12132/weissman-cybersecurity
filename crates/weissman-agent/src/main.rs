//! Weissman Endpoint Agent — entry point.
//!
//! Boot sequence:
//!   1. parse CLI / env (`--server-url`, `--enrollment-token`, `--client-id`).
//!   2. enroll over HTTPS, obtain a per-agent session JWT + agent_id.
//!   3. open a WebSocket to `/ws/agent`, send `hello`, await `task` messages.
//!   4. for each task: spawn local detection, stream `finding` messages, then `task_done`.
//!   5. reconnect with exponential backoff on disconnect.
//!
//! No persistent storage; all state in memory.

mod detections;
mod protocol;
mod transport;

use clap::Parser;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(name = "weissman-agent", version, about = "Weissman Endpoint Agent")]
struct Cli {
    /// Full URL of the Weissman server (e.g. https://api.weissman.io).
    #[arg(long, env = "WEISSMAN_SERVER_URL")]
    server_url: String,

    /// One-time enrollment token issued by the dashboard.
    #[arg(long, env = "WEISSMAN_ENROLLMENT_TOKEN")]
    enrollment_token: String,

    /// Optional: numeric client_id this agent belongs to.
    #[arg(long, env = "WEISSMAN_CLIENT_ID")]
    client_id: Option<i64>,

    /// Override hostname reported during enrollment (defaults to `hostname::get()`).
    #[arg(long, env = "WEISSMAN_AGENT_HOSTNAME")]
    hostname_override: Option<String>,

    /// Heartbeat interval in seconds.
    #[arg(long, default_value_t = 30, env = "WEISSMAN_HEARTBEAT_SECONDS")]
    heartbeat_secs: u64,

    /// Initial reconnect backoff in milliseconds (doubles up to 60s).
    #[arg(long, default_value_t = 1500, env = "WEISSMAN_BACKOFF_MS")]
    backoff_ms_initial: u64,

    /// Print enrollment info and exit (for systemd / setup automation).
    #[arg(long)]
    enroll_only: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = Cli::parse();
    info!(target: "agent", "Weissman endpoint agent starting (version={})", env!("CARGO_PKG_VERSION"));

    let hostname = cli
        .hostname_override
        .clone()
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| format!("unknown-host-{}", std::process::id()));

    // Identity is persisted, so an enrollment token is consumed at most once in this agent's
    // lifetime. Previously `enroll()` ran unconditionally on every start against a strictly
    // single-use token: the second start — systemd restart, reboot, crash, or the installer's own
    // `Restart=always` — got HTTP 401 and the process exited. Nothing ever stayed up.
    let state_path = transport::state::state_path();
    let mut enrollment = match transport::state::load(&state_path) {
        Some(saved) => {
            info!(
                target: "agent", agent_id = %saved.agent_id, state = %state_path.display(),
                "resuming persisted identity"
            );
            let jwt = transport::enrollment::renew_session(
                &cli.server_url,
                &saved.agent_id,
                &saved.agent_secret,
                env!("CARGO_PKG_VERSION"),
            )
            .await?;
            saved.into_enrollment(jwt)
        }
        None => {
            let fresh = transport::enrollment::enroll(
                &cli.server_url,
                &cli.enrollment_token,
                cli.client_id,
                &hostname,
                whoami::devicename(),
                std::env::consts::OS,
                std::env::consts::ARCH,
                env!("CARGO_PKG_VERSION"),
            )
            .await?;
            info!(target: "agent", agent_id = %fresh.agent_id, tenant_id = fresh.tenant_id, client_id = fresh.client_id, "enrollment ok");
            // Persist BEFORE doing anything else: the token is now spent, so if we crash before
            // writing this the agent can never come back.
            if fresh.agent_secret.trim().is_empty() {
                warn!(
                    target: "agent",
                    "server returned no agent_secret — this agent cannot renew its session and \
                     will go dark when the JWT expires; upgrade the server"
                );
            } else if let Err(e) = transport::state::save(
                &state_path,
                &transport::state::AgentState::from_enrollment(&fresh),
            ) {
                error!(
                    target: "agent", path = %state_path.display(), error = %e,
                    "could not persist agent identity — a restart will fail, because the \
                     enrollment token has already been consumed"
                );
            }
            fresh
        }
    };

    if cli.enroll_only {
        // The installer runs this to validate the token. It used to throw the result away and
        // hand the SAME (now consumed) token to the service, so every install crash-looped while
        // reporting success. The enrollment is persisted above, so the service starts from state.
        println!("{}", serde_json::to_string_pretty(&enrollment)?);
        return Ok(());
    }

    detections::ot_plc_decoy::spawn();

    // Reconnect loop with exponential back-off.
    let mut backoff = cli.backoff_ms_initial.max(250);
    loop {
        match transport::websocket::run_session(&cli.server_url, &enrollment, cli.heartbeat_secs)
            .await
        {
            Ok(()) => {
                info!(target: "agent", "session ended cleanly; reconnecting in {}ms", backoff);
            }
            Err(e) => {
                error!(target: "agent", error = %e, "session error; reconnecting in {}ms", backoff);
            }
        }
        tokio::time::sleep(Duration::from_millis(backoff)).await;
        backoff = (backoff.saturating_mul(2)).min(60_000);

        // Re-mint the session JWT before every reconnect. It is short-lived
        // (WEISSMAN_AGENT_JWT_TTL_MINS, default 240) and there was previously no way to renew it,
        // so an agent that stayed up simply went dark four hours after enrolling and never came
        // back. Renewal failure is not fatal: keep the existing token and retry on the next loop,
        // because a transient server outage must not end the agent's life.
        if !enrollment.agent_secret.trim().is_empty() {
            match transport::enrollment::renew_session(
                &cli.server_url,
                &enrollment.agent_id,
                &enrollment.agent_secret,
                env!("CARGO_PKG_VERSION"),
            )
            .await
            {
                Ok(jwt) => enrollment.session_jwt = jwt,
                Err(e) => warn!(
                    target: "agent", error = %e,
                    "session renewal failed; reusing the current token for this attempt"
                ),
            }
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,agent=info,reqwest=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .compact()
        .try_init();
    if std::env::var("WEISSMAN_AGENT_LOG_QUIET").is_ok() {
        warn!(target: "agent", "WEISSMAN_AGENT_LOG_QUIET set — using compact format");
    }
}
