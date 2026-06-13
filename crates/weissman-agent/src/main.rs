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

    let enrollment = transport::enrollment::enroll(
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

    info!(target: "agent", agent_id = %enrollment.agent_id, tenant_id = enrollment.tenant_id, client_id = enrollment.client_id, "enrollment ok");
    if cli.enroll_only {
        println!("{}", serde_json::to_string_pretty(&enrollment)?);
        return Ok(());
    }

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
