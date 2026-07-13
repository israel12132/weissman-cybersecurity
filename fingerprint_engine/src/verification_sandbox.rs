//! 200% verification: shallow-clone target repo, bind-mount into ephemeral Docker, run PoC, apply patch on host, restart container, re-run PoC and require the exploit no longer returns success (2xx).
//!
//! Requires `git`, `patch`, Docker socket access, and a container image whose default CMD serves the app from `/app` (bind-mounted repository).

use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, RestartContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::models::{HostConfig, PortBinding};
use bollard::Docker;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use uuid::Uuid;

const EXPLOIT_TIMEOUT_MS: u64 = 20000;
const MAX_PATCH_BYTES: usize = 512 * 1024;
const CONTAINER_READY_WAIT_SECS: u64 = 2;
const CONTAINER_START_ROUNDS: u32 = 30;
/// Guardrails for the applied-fix capture: never open a PR with a runaway tree.
const MAX_CHANGED_FILES: usize = 60;
const MAX_CHANGED_BYTES: usize = 1_500_000;

/// Outcome of the sandbox verification. `Fixed` is the ONLY verdict that opens a PR.
/// `BrokeApp` guards the previous hole where a patch that crashed the app (5xx /
/// connection-refused ⇒ "not 2xx") was mis-scored as a successful remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum HealVerdict {
    /// Baseline was exploitable, the app is still healthy, and the exploit is now blocked.
    Fixed,
    /// The exploit still succeeds after the patch.
    StillVulnerable,
    /// The patch took the app down (5xx / unreachable) instead of fixing the vuln.
    BrokeApp,
    /// Could not reach a confident conclusion (e.g. baseline was not exploitable).
    Inconclusive,
}

impl HealVerdict {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            HealVerdict::Fixed => "fixed",
            HealVerdict::StillVulnerable => "still_vulnerable",
            HealVerdict::BrokeApp => "broke_app",
            HealVerdict::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationStep {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub ts: i64,
}

#[derive(Debug)]
pub struct VerificationResult {
    pub verified: bool,
    pub verdict: HealVerdict,
    pub container_id: Option<String>,
    pub baseline_status: u16,
    pub after_patch_status: u16,
    pub baseline_was_vulnerable: bool,
    pub exploit_neutralized: bool,
    /// Post-patch health/control probe: is the app still serving after the fix?
    pub health_after_ok: bool,
    pub health_status: u16,
    /// Repo-relative path → new full content of every file the patch changed, read from
    /// the sandbox clone AFTER the patch applied and the exploit was proven closed. These
    /// are committed verbatim so the PR contains the real, mergeable fix (not a `PATCH.txt`).
    pub changed_files: Vec<(String, String)>,
    /// Paths the patch deleted (or binary files) that the blob-tree commit path can't apply;
    /// surfaced in the PR body for honesty rather than silently dropped.
    pub deleted_paths: Vec<String>,
    /// Regression-test gate (opt-in): whether the repo's own tests ran in-container after the
    /// patch, whether they passed, and a truncated tail of their output.
    pub tests_ran: bool,
    pub tests_passed: bool,
    pub test_output: String,
    pub error: Option<String>,
    pub steps: Vec<VerificationStep>,
}

/// Step capture for verification: in-memory (tests/UI) or durable Postgres (worker).
#[derive(Clone)]
pub enum StepSink {
    Memory(Arc<tokio::sync::Mutex<Vec<VerificationStep>>>),
    Postgres {
        pool: PgPool,
        tenant_id: i64,
        job_id: Uuid,
        seq: Arc<AtomicI32>,
    },
}

async fn push_step(sink: &Option<StepSink>, step: &str, detail: Option<String>) {
    let ts = chrono::Utc::now().timestamp();
    match sink {
        None => {}
        Some(StepSink::Memory(m)) => {
            let mut g = m.lock().await;
            g.push(VerificationStep {
                step: step.to_string(),
                detail,
                ts,
            });
        }
        Some(StepSink::Postgres {
            pool,
            tenant_id,
            job_id,
            seq,
        }) => {
            let idx = seq.fetch_add(1, Ordering::SeqCst);
            let detail_ref = detail.as_deref();
            match pool.acquire().await {
                Ok(mut conn) => {
                    if let Err(e) = crate::db::set_tenant_conn(&mut *conn, *tenant_id).await {
                        tracing::error!(target: "verification_sandbox", error = %e, "set_tenant_conn for step log");
                    } else if let Err(e) = sqlx::query(
                        r#"INSERT INTO heal_verification_steps
                           (tenant_id, job_id, step_index, step_label, detail, step_ts)
                           VALUES ($1, $2, $3, $4, $5, $6)"#,
                    )
                    .bind(*tenant_id)
                    .bind(*job_id)
                    .bind(idx)
                    .bind(step)
                    .bind(detail_ref)
                    .bind(ts)
                    .execute(&mut *conn)
                    .await
                    {
                        tracing::error!(target: "verification_sandbox", error = %e, "heal_verification_steps insert");
                    }
                }
                Err(e) => {
                    tracing::error!(target: "verification_sandbox", error = %e, "pool acquire for step log")
                }
            }
        }
    }
}

fn require_baseline_success() -> bool {
    std::env::var("WEISSMAN_VERIFY_REQUIRE_BEFORE_SUCCESS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|n: &f64| *n > 0.0)
        .unwrap_or(default)
}

/// When true (default), the post-patch health probe must succeed for a `Fixed` verdict, so a
/// patch that crashes the app is scored `BrokeApp`. Set `WEISSMAN_VERIFY_REQUIRE_HEALTH=0` for
/// targets without a usable health endpoint.
fn require_health() -> bool {
    std::env::var("WEISSMAN_VERIFY_REQUIRE_HEALTH")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true)
}

/// Pure verdict decision from the post-patch signals. `app_up` already folds in the
/// health-required policy (health probe result when required, else `true`). `baseline_proven`
/// means the baseline exploit was confirmed to work (or the baseline gate was overridden).
///
/// - `BrokeApp`  — exploit route errors (5xx / unreachable) or the app is no longer healthy.
/// - `StillVulnerable` — exploit still returns a 2xx success.
/// - `Fixed`     — exploit now 3xx/4xx (redirected/blocked) AND the app is still up.
/// - `Inconclusive` — baseline unproven or an unclassifiable status.
#[must_use]
pub fn classify_verdict(baseline_proven: bool, after_status: u16, app_up: bool) -> HealVerdict {
    if !baseline_proven {
        return HealVerdict::Inconclusive;
    }
    let exploit_still_succeeds = (200..=299).contains(&after_status);
    let exploit_errored = after_status == 0 || (500..600).contains(&after_status);
    if exploit_errored || !app_up {
        HealVerdict::BrokeApp
    } else if exploit_still_succeeds {
        HealVerdict::StillVulnerable
    } else if (300..500).contains(&after_status) {
        HealVerdict::Fixed
    } else {
        HealVerdict::Inconclusive
    }
}

/// Parse a minimal subset of curl: `-X`, `-H`, `-d`, `--data`, URL.
pub fn parse_curl_request(
    curl: &str,
) -> Result<
    (
        reqwest::Method,
        String,
        reqwest::header::HeaderMap,
        Option<Vec<u8>>,
    ),
    String,
> {
    let mut method = reqwest::Method::GET;
    let mut headers = reqwest::header::HeaderMap::new();
    let mut body: Option<Vec<u8>> = None;
    let mut url: Option<String> = None;
    let parts: Vec<&str> = curl.split_whitespace().collect();
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "curl" => {
                i += 1;
            }
            "-X" | "--request" => {
                if i + 1 < parts.len() {
                    method = reqwest::Method::from_bytes(parts[i + 1].as_bytes())
                        .unwrap_or(reqwest::Method::GET);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-H" | "--header" => {
                if i + 1 < parts.len() {
                    let h = parts[i + 1].trim_matches('"').trim_matches('\'');
                    if let Some((k, v)) = h.split_once(':') {
                        let name = reqwest::header::HeaderName::from_bytes(k.trim().as_bytes())
                            .map_err(|e| format!("bad header name: {}", e))?;
                        let val = reqwest::header::HeaderValue::from_str(v.trim())
                            .map_err(|e| format!("bad header value: {}", e))?;
                        headers.insert(name, val);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-d" | "--data" | "--data-raw" => {
                if i + 1 < parts.len() {
                    let d = parts[i + 1].trim_matches('"').trim_matches('\'');
                    body = Some(d.as_bytes().to_vec());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-k" | "--insecure" => {
                i += 1;
            }
            s if s.starts_with("http://") || s.starts_with("https://") => {
                url = Some(s.trim_matches('\'').trim_matches('"').to_string());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    let url = url.ok_or_else(|| "could not find URL in curl command".to_string())?;
    Ok((method, url, headers, body))
}

pub fn rewrite_localhost_url(url: &str, host: &str, port: u16) -> String {
    if let Ok(mut u) = url::Url::parse(url) {
        let _ = u.set_host(Some(host));
        let _ = u.set_port(Some(port));
        // Downgrade to http for plain mapped port unless URL was https
        if u.scheme() == "https" {
            let _ = u.set_scheme("http").ok();
        }
        return u.to_string();
    }
    format!("http://{}:{}/", host, port)
}

pub async fn http_probe(
    method: reqwest::Method,
    url: &str,
    headers: &reqwest::header::HeaderMap,
    body: Option<&[u8]>,
) -> (u16, String) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(EXPLOIT_TIMEOUT_MS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (0, "client build failed".into()),
    };
    let mut req = client.request(method.clone(), url);
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return (0, e.to_string()),
    };
    let status = resp.status().as_u16();
    let txt = resp.text().await.unwrap_or_default();
    (status, txt.chars().take(512).collect())
}

async fn git_clone_shallow(
    repo_slug: &str,
    branch: &str,
    token: &str,
    git_host: &str,
    dest: &Path,
) -> Result<(), String> {
    // Provider-aware token clone URL: GitHub uses `x-access-token`, GitLab uses `oauth2`.
    let host = {
        let h = git_host.trim();
        if h.is_empty() {
            "github.com"
        } else {
            h
        }
    };
    let url = if host.contains("gitlab") {
        format!("https://oauth2:{}@{}/{}.git", token, host, repo_slug)
    } else {
        format!(
            "https://x-access-token:{}@{}/{}.git",
            token, host, repo_slug
        )
    };
    // Testability / self-hosted escape hatch: clone from an explicit URL (e.g. file:///…) instead
    // of the token-derived URL, so the full pipeline can run against a local bare repo with no
    // network. Ignored when unset/empty.
    let url = std::env::var("WEISSMAN_VERIFY_CLONE_URL_OVERRIDE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(url);
    let mut cmd = Command::new("git");
    cmd.arg("clone").arg("--depth").arg("1");
    if !branch.trim().is_empty() {
        cmd.arg("--branch").arg(branch);
    }
    cmd.arg(&url).arg(dest);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let out = cmd
        .output()
        .await
        .map_err(|e| format!("git spawn: {}", e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git clone failed: {}",
            err.chars().take(400).collect::<String>()
        ));
    }
    Ok(())
}

pub async fn apply_unified_patch(repo_dir: &Path, patch_file: &Path) -> Result<String, String> {
    for plevel in [1i32, 0] {
        let out = Command::new("patch")
            .arg(format!("-p{}", plevel))
            .arg("-i")
            .arg(patch_file)
            .arg("--batch")
            .current_dir(repo_dir)
            .output()
            .await
            .map_err(|e| format!("patch spawn: {}", e))?;
        if out.status.success() {
            return Ok(format!("patch applied with -p{}", plevel));
        }
    }
    let stderr = Command::new("patch")
        .arg("-p1")
        .arg("-i")
        .arg(patch_file)
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    Err(format!(
        "patch failed: {}",
        String::from_utf8_lossy(&stderr.stderr)
            .chars()
            .take(500)
            .collect::<String>()
    ))
}

/// After the patch applied in the sandbox clone, enumerate the files it actually changed
/// and read their post-patch content. This is what gets committed so the PR contains the
/// real applied fix. Additions and modifications (including rename targets) are captured;
/// deletions are reported as a summary note but not applied via the blob-tree commit path.
///
/// Returns `Err` when the patch produced no capturable changes (so the job fails loudly
/// instead of opening an empty PR) or when the change set blows past the guardrails.
pub async fn collect_changed_files(
    repo_dir: &Path,
) -> Result<(Vec<(String, String)>, Vec<String>), String> {
    // Stage everything so `diff --cached` reports adds, mods, renames and deletes uniformly.
    let add = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("add")
        .arg("-A")
        .output()
        .await
        .map_err(|e| format!("git add spawn: {}", e))?;
    if !add.status.success() {
        return Err(format!(
            "git add -A failed: {}",
            String::from_utf8_lossy(&add.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }

    let diff = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("-c")
        .arg("core.quotepath=false")
        .arg("diff")
        .arg("--cached")
        .arg("--name-status")
        .output()
        .await
        .map_err(|e| format!("git diff spawn: {}", e))?;
    if !diff.status.success() {
        return Err(format!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&diff.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }

    let listing = String::from_utf8_lossy(&diff.stdout);
    let mut files: Vec<(String, String)> = Vec::new();
    let mut deleted: Vec<String> = Vec::new();
    let mut total_bytes: usize = 0;

    for line in listing.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let status = cols.next().unwrap_or("");
        // For renames/copies (R100 / C100) the interesting path is the destination (last column).
        let path = if status.starts_with('R') || status.starts_with('C') {
            cols.last().unwrap_or("").to_string()
        } else {
            cols.next().unwrap_or("").to_string()
        };
        if path.is_empty() {
            continue;
        }
        let code = status.chars().next().unwrap_or(' ');
        match code {
            'D' => {
                deleted.push(path);
            }
            'A' | 'M' | 'R' | 'C' | 'T' => {
                // Fail fast on count and size (via metadata) BEFORE buffering the file into memory,
                // so an oversized staged file can't cause a transient host-side memory spike.
                if files.len() >= MAX_CHANGED_FILES {
                    return Err(format!(
                        "patch changes more than {} files — refusing to auto-commit",
                        MAX_CHANGED_FILES
                    ));
                }
                let full = repo_dir.join(&path);
                if let Ok(meta) = tokio::fs::metadata(&full).await {
                    if total_bytes.saturating_add(meta.len() as usize) > MAX_CHANGED_BYTES {
                        return Err(format!(
                            "patched files exceed {} bytes — refusing to auto-commit",
                            MAX_CHANGED_BYTES
                        ));
                    }
                }
                let content = match tokio::fs::read(&full).await {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            // Binary file: skip content but note it so the PR body is honest.
                            deleted.push(format!("{} (binary, not committed via API)", path));
                            continue;
                        }
                    },
                    Err(e) => return Err(format!("read changed file {}: {}", path, e)),
                };
                total_bytes = total_bytes.saturating_add(content.len());
                // Re-check the exact byte total after decoding (metadata is an upper-bound guard).
                if total_bytes > MAX_CHANGED_BYTES {
                    return Err(format!(
                        "patched files exceed {} bytes — refusing to auto-commit",
                        MAX_CHANGED_BYTES
                    ));
                }
                files.push((path, content));
            }
            _ => {}
        }
    }

    if files.is_empty() {
        return Err("patch produced no committable file changes".into());
    }
    Ok((files, deleted))
}

/// Opt-in: run the repo's own test suite in-container as a regression gate.
fn run_tests_enabled() -> bool {
    std::env::var("WEISSMAN_VERIFY_RUN_TESTS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Return the last `n` characters of `s` (UTF-8 safe), for log/output tails.
fn tail_chars(s: &str, n: usize) -> String {
    let v: Vec<char> = s.chars().collect();
    if v.len() > n {
        v[v.len() - n..].iter().collect()
    } else {
        s.to_string()
    }
}

/// Resolve the repo's test command from its manifests (Node/Rust/Go/Python). `None` when no
/// recognized test setup is present, so the gate simply doesn't run.
fn detect_test_command(repo_dir: &Path) -> Option<Vec<String>> {
    let sh = |c: &str| Some(vec!["sh".to_string(), "-lc".to_string(), c.to_string()]);
    let pkg = repo_dir.join("package.json");
    if pkg.exists() {
        if let Ok(txt) = std::fs::read_to_string(&pkg) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                let test = v
                    .get("scripts")
                    .and_then(|s| s.get("test"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                if !test.trim().is_empty() && !test.contains("no test specified") {
                    return sh("npm test --silent");
                }
            }
        }
    }
    if repo_dir.join("Cargo.toml").exists() {
        return sh("cargo test --quiet");
    }
    if repo_dir.join("go.mod").exists() {
        return sh("go test ./...");
    }
    if repo_dir.join("requirements.txt").exists()
        || repo_dir.join("pyproject.toml").exists()
        || repo_dir.join("pytest.ini").exists()
    {
        return sh("pytest -q");
    }
    None
}

/// Execute `cmd` inside the running container (working dir `/app`) and return (passed, output).
async fn run_tests_in_container(docker: &Docker, id: &str, cmd: &[String]) -> (bool, String) {
    use bollard::exec::{CreateExecOptions, StartExecResults};
    use futures::StreamExt;

    let exec = match docker
        .create_exec(
            id,
            CreateExecOptions {
                cmd: Some(cmd.iter().map(|s| s.as_str()).collect()),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                working_dir: Some("/app"),
                ..Default::default()
            },
        )
        .await
    {
        Ok(e) => e,
        Err(e) => return (false, format!("create_exec: {e}")),
    };

    let mut output = String::new();
    match docker.start_exec(&exec.id, None).await {
        Ok(StartExecResults::Attached {
            output: mut out, ..
        }) => {
            while let Some(chunk) = out.next().await {
                if let Ok(msg) = chunk {
                    output.push_str(&msg.to_string());
                    if output.len() > 20_000 {
                        break;
                    }
                }
            }
        }
        Ok(StartExecResults::Detached) => {}
        Err(e) => return (false, format!("start_exec: {e}")),
    }

    let passed = matches!(
        docker.inspect_exec(&exec.id).await,
        Ok(d) if d.exit_code.unwrap_or(1) == 0
    );
    (passed, output)
}

fn host_port_from_inspect(
    inspect: &bollard::models::ContainerInspectResponse,
    container_port: u16,
) -> Result<u16, String> {
    let ports = inspect
        .network_settings
        .as_ref()
        .and_then(|n| n.ports.as_ref())
        .ok_or_else(|| "no port bindings".to_string())?;
    let key = format!("{}/tcp", container_port);
    let binds = ports
        .get(&key)
        .ok_or_else(|| format!("no binding for {}", key))?;
    let first = binds
        .as_ref()
        .and_then(|v| v.first())
        .ok_or_else(|| "empty port binding".to_string())?;
    let hp = first
        .host_port
        .as_ref()
        .ok_or_else(|| "no host_port".to_string())?;
    hp.parse::<u16>().map_err(|_| "bad host port".to_string())
}

/// Full pipeline: clone repo → Docker bind-mount `/app` → baseline HTTP → patch on host → restart → HTTP must not be 2xx.
pub async fn verify_patch_ephemeral_docker(
    docker_socket: &str,
    image: &str,
    container_port: u16,
    repo_slug: &str,
    base_branch: &str,
    git_token: &str,
    git_host: &str,
    patch_content: &str,
    poc_curl: &str,
    health_check_curl: &str,
    step_sink: Option<StepSink>,
) -> VerificationResult {
    let sink = step_sink;

    macro_rules! step {
        ($n:expr, $d:expr) => {
            push_step(&sink, $n, $d).await;
        };
    }

    if patch_content.len() > MAX_PATCH_BYTES {
        push_step(
            &sink,
            "failed",
            Some(format!("patch exceeds {} bytes", MAX_PATCH_BYTES)),
        )
        .await;
        return VerificationResult {
            verified: false,
            verdict: HealVerdict::Inconclusive,
            container_id: None,
            baseline_status: 0,
            after_patch_status: 0,
            baseline_was_vulnerable: false,
            exploit_neutralized: false,
            health_after_ok: false,
            health_status: 0,
            changed_files: Vec::new(),
            deleted_paths: Vec::new(),
            tests_ran: false,
            tests_passed: false,
            test_output: String::new(),
            error: Some(format!("patch exceeds {} bytes", MAX_PATCH_BYTES)),
            steps: collect_steps_only(&sink).await,
        };
    }

    step!("init", Some("Starting 200% verification pipeline".into()));

    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return fail(&sink, format!("tempdir: {}", e)).await;
        }
    };
    let repo_dir = tmp.path().join("repo");
    step!(
        "git_clone",
        Some(format!("Cloning {}/{}", repo_slug, base_branch))
    );

    if let Err(e) = git_clone_shallow(repo_slug, base_branch, git_token, git_host, &repo_dir).await
    {
        return fail(&sink, e).await;
    }

    let patch_path = tmp.path().join("weissman_verify.patch");
    if let Err(e) = tokio::fs::write(&patch_path, patch_content).await {
        return fail(&sink, format!("write patch: {}", e)).await;
    }

    let (method, url_tpl, hdrs, body) = match parse_curl_request(poc_curl) {
        Ok(x) => x,
        Err(e) => {
            return fail(&sink, e).await;
        }
    };

    step!(
        "docker_connect",
        Some(format!("Connecting {}", docker_socket))
    );
    let docker = match Docker::connect_with_socket(docker_socket, 120, bollard::API_DEFAULT_VERSION)
    {
        Ok(d) => d,
        Err(e) => {
            return fail(&sink, format!("Docker connect: {}", e)).await;
        }
    };

    let cname = format!(
        "weissman_vfy_{}",
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("x")
    );
    let mount = format!("{}:/app:rw", repo_dir.display());

    let mut port_map: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    port_map.insert(
        format!("{}/tcp", container_port),
        Some(vec![PortBinding {
            host_ip: Some("0.0.0.0".into()),
            host_port: Some("0".into()),
        }]),
    );

    let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
    exposed.insert(format!("{}/tcp", container_port), HashMap::new());

    // Harden the ephemeral container: cap memory/CPU/pids and drop all Linux capabilities so a
    // hostile repo or a runaway app can't exhaust the host or escalate. Bridge networking is kept
    // because the exploit/health probes reach the app via a host-published mapped port.
    let mem_bytes: i64 = env_u64("WEISSMAN_VERIFY_MEM_MB", 1024).saturating_mul(1024 * 1024) as i64;
    let nano_cpus: i64 = (env_f64("WEISSMAN_VERIFY_CPUS", 1.0) * 1_000_000_000.0) as i64;
    let pids_limit: i64 = env_u64("WEISSMAN_VERIFY_PIDS", 512) as i64;
    let host_config = HostConfig {
        binds: Some(vec![mount]),
        port_bindings: Some(port_map),
        memory: Some(mem_bytes),
        memory_swap: Some(mem_bytes), // == memory ⇒ no swap
        nano_cpus: Some(nano_cpus),
        pids_limit: Some(pids_limit),
        cap_drop: Some(vec!["ALL".to_string()]),
        security_opt: Some(vec!["no-new-privileges".to_string()]),
        ..Default::default()
    };

    let config = Config {
        image: Some(image.to_string()),
        host_config: Some(host_config),
        exposed_ports: Some(exposed),
        ..Default::default()
    };

    step!(
        "container_create",
        Some(format!("Image {} port {}", image, container_port))
    );
    let create = match docker
        .create_container(
            Some(CreateContainerOptions {
                name: cname.clone(),
                platform: None,
            }),
            config,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return fail(&sink, format!("Create container: {}", e)).await;
        }
    };
    let id = create.id.clone();

    if let Err(e) = docker
        .start_container(&id, None::<StartContainerOptions<String>>)
        .await
    {
        let _ = docker
            .remove_container(&id, None::<RemoveContainerOptions>)
            .await;
        return fail(&sink, format!("Start: {}", e)).await;
    }

    step!("container_start", Some(id.clone()));

    let mut host_bind_port = 0u16;
    for _ in 0..CONTAINER_START_ROUNDS {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(ins) = docker.inspect_container(&id, None).await {
            if let Ok(p) = host_port_from_inspect(&ins, container_port) {
                host_bind_port = p;
                break;
            }
        }
    }
    if host_bind_port == 0 {
        let _ = docker
            .stop_container(&id, Some(StopContainerOptions { t: 5 }))
            .await;
        let _ = docker
            .remove_container(&id, None::<RemoveContainerOptions>)
            .await;
        return fail(&sink, "Could not resolve host port mapping".into()).await;
    }

    tokio::time::sleep(Duration::from_secs(CONTAINER_READY_WAIT_SECS)).await;

    let target_url = rewrite_localhost_url(&url_tpl, "127.0.0.1", host_bind_port);
    step!(
        "exploit_baseline",
        Some(format!(
            "PoC against {} (mapped {})",
            target_url, host_bind_port
        ))
    );

    let (baseline_status, baseline_body) =
        http_probe(method.clone(), &target_url, &hdrs, body.as_deref()).await;
    let baseline_was_vulnerable = (200..300).contains(&baseline_status);
    step!(
        "exploit_baseline_result",
        Some(format!(
            "HTTP {} {}",
            baseline_status,
            baseline_body.chars().take(120).collect::<String>()
        ))
    );

    if require_baseline_success() && !baseline_was_vulnerable {
        cleanup_container(&docker, &id).await;
        step!(
            "failed",
            Some("Baseline was not a successful 2xx — cannot prove remediation".into())
        );
        return VerificationResult {
            verified: false,
            verdict: HealVerdict::Inconclusive,
            container_id: Some(id),
            baseline_status,
            after_patch_status: 0,
            baseline_was_vulnerable: false,
            exploit_neutralized: false,
            health_after_ok: false,
            health_status: 0,
            changed_files: Vec::new(),
            deleted_paths: Vec::new(),
            tests_ran: false,
            tests_passed: false,
            test_output: String::new(),
            error: Some(
                "Baseline did not return 2xx; set WEISSMAN_VERIFY_REQUIRE_BEFORE_SUCCESS=0 to override"
                    .into(),
            ),
            steps: collect_steps_only(&sink).await,
        };
    }

    step!("apply_patch_host", Some("patch -p1 in cloned repo".into()));
    if let Err(e) = apply_unified_patch(&repo_dir, &patch_path).await {
        cleanup_container(&docker, &id).await;
        return fail(&sink, e).await;
    }

    // Capture the ACTUAL applied files now (while they're on disk) so the PR contains the
    // real fix. An empty/oversized change set is a hard verification failure — never a PR.
    let (changed_files, deleted_paths) = match collect_changed_files(&repo_dir).await {
        Ok(v) => v,
        Err(e) => {
            cleanup_container(&docker, &id).await;
            return fail(&sink, format!("capture applied fix: {}", e)).await;
        }
    };
    step!(
        "applied_fix_captured",
        Some(format!(
            "{} file(s) changed{}",
            changed_files.len(),
            if deleted_paths.is_empty() {
                String::new()
            } else {
                format!(", {} deletion(s) noted", deleted_paths.len())
            }
        ))
    );

    step!("container_restart", None);
    if let Err(e) = docker
        .restart_container(&id, Some(RestartContainerOptions { t: 15 }))
        .await
    {
        cleanup_container(&docker, &id).await;
        return fail(&sink, format!("restart: {}", e)).await;
    }
    tokio::time::sleep(Duration::from_secs(CONTAINER_READY_WAIT_SECS)).await;

    let (after_status, after_body) =
        http_probe(method.clone(), &target_url, &hdrs, body.as_deref()).await;
    step!(
        "exploit_after_patch",
        Some(format!(
            "HTTP {} {}",
            after_status,
            after_body.chars().take(120).collect::<String>()
        ))
    );

    // Health / control probe: confirm the app is STILL SERVING after the patch, so a fix that
    // simply crashes the endpoint (5xx / connection-refused) is not mistaken for a remediation.
    let (health_method, health_url) = match parse_curl_request(health_check_curl) {
        Ok((m, u, _, _)) => (m, rewrite_localhost_url(&u, "127.0.0.1", host_bind_port)),
        Err(_) => (
            reqwest::Method::GET,
            format!("http://127.0.0.1:{}/", host_bind_port),
        ),
    };
    let (health_status, _health_body) = http_probe(
        health_method,
        &health_url,
        &reqwest::header::HeaderMap::new(),
        None,
    )
    .await;
    let health_after_ok = (200..400).contains(&health_status);
    step!(
        "health_after_patch",
        Some(format!("HTTP {} on {}", health_status, health_url))
    );

    let app_up = if require_health() {
        health_after_ok
    } else {
        true
    };
    let baseline_proven = baseline_was_vulnerable || !require_baseline_success();
    let mut verdict = classify_verdict(baseline_proven, after_status, app_up);
    let exploit_neutralized = !(200..=299).contains(&after_status);

    // Optional regression-test gate: if the exploit/health checks pass, run the repo's own tests
    // in-container. A fix that breaks the test suite is downgraded to `BrokeApp` (not a valid fix).
    let mut tests_ran = false;
    let mut tests_passed = false;
    let mut test_output = String::new();
    if verdict == HealVerdict::Fixed && run_tests_enabled() {
        if let Some(cmd) = detect_test_command(&repo_dir) {
            step!(
                "regression_tests",
                Some(format!("running: {}", cmd.join(" ")))
            );
            let (passed, out) = run_tests_in_container(&docker, &id, &cmd).await;
            tests_ran = true;
            tests_passed = passed;
            test_output = tail_chars(&out, 2000);
            step!(
                if passed {
                    "regression_tests_passed"
                } else {
                    "regression_tests_failed"
                },
                Some(tail_chars(&test_output, 300))
            );
            if !passed {
                verdict = HealVerdict::BrokeApp;
            }
        } else {
            step!(
                "regression_tests_skipped",
                Some("no recognized test command in the repo".into())
            );
        }
    }
    let verified = verdict == HealVerdict::Fixed;

    cleanup_container(&docker, &id).await;
    let verdict_step = match verdict {
        HealVerdict::Fixed => "verdict_fixed",
        HealVerdict::StillVulnerable => "verdict_still_vulnerable",
        HealVerdict::BrokeApp => "verdict_broke_app",
        HealVerdict::Inconclusive => "verdict_inconclusive",
    };
    let verdict_detail = match verdict {
        HealVerdict::Fixed => format!(
            "Exploit closed (HTTP {}) and app healthy (HTTP {}){} — PR may be opened",
            after_status,
            health_status,
            if tests_ran { ", tests passed" } else { "" }
        ),
        HealVerdict::StillVulnerable => {
            format!("Exploit still returns success (HTTP {})", after_status)
        }
        HealVerdict::BrokeApp => {
            if tests_ran && !tests_passed {
                "Patch regressed the app's own test suite — NOT a valid fix".to_string()
            } else {
                format!(
                    "Patch broke the app: exploit HTTP {}, health HTTP {} — NOT a valid fix",
                    after_status, health_status
                )
            }
        }
        HealVerdict::Inconclusive => format!(
            "Inconclusive: exploit HTTP {}, health HTTP {}",
            after_status, health_status
        ),
    };
    step!(verdict_step, Some(verdict_detail));

    VerificationResult {
        verified,
        verdict,
        container_id: Some(id),
        baseline_status,
        after_patch_status: after_status,
        baseline_was_vulnerable,
        exploit_neutralized,
        health_after_ok,
        health_status,
        changed_files,
        deleted_paths,
        tests_ran,
        tests_passed,
        test_output,
        error: if verified {
            None
        } else {
            Some(format!(
                "verdict={} (exploit HTTP {}, health HTTP {})",
                verdict.as_str(),
                after_status,
                health_status
            ))
        },
        steps: collect_steps_only(&sink).await,
    }
}

/// Append a named step to a live sink (reuses the sink's shared sequence counter), so callers
/// outside this module (e.g. the self-repair loop) can annotate the verification timeline.
pub async fn record_step(sink: &StepSink, step: &str, detail: Option<String>) {
    push_step(&Some(sink.clone()), step, detail).await;
}

async fn cleanup_container(docker: &Docker, id: &str) {
    let _ = docker
        .stop_container(id, Some(StopContainerOptions { t: 8 }))
        .await;
    let _ = docker
        .remove_container(id, None::<RemoveContainerOptions>)
        .await;
}

async fn fail(sink: &Option<StepSink>, msg: String) -> VerificationResult {
    push_step(sink, "failed", Some(msg.clone())).await;
    VerificationResult {
        verified: false,
        verdict: HealVerdict::Inconclusive,
        container_id: None,
        baseline_status: 0,
        after_patch_status: 0,
        baseline_was_vulnerable: false,
        exploit_neutralized: false,
        health_after_ok: false,
        health_status: 0,
        changed_files: Vec::new(),
        deleted_paths: Vec::new(),
        tests_ran: false,
        tests_passed: false,
        test_output: String::new(),
        error: Some(msg),
        steps: collect_steps_only(sink).await,
    }
}

async fn collect_steps_only(sink: &Option<StepSink>) -> Vec<VerificationStep> {
    match sink {
        None => Vec::new(),
        Some(StepSink::Memory(m)) => m.lock().await.clone(),
        Some(StepSink::Postgres {
            pool,
            tenant_id,
            job_id,
            ..
        }) => {
            let Ok(mut conn) = pool.acquire().await else {
                return Vec::new();
            };
            if crate::db::set_tenant_conn(&mut *conn, *tenant_id)
                .await
                .is_err()
            {
                return Vec::new();
            }
            let rows = sqlx::query(
                r#"SELECT step_label, detail, step_ts FROM heal_verification_steps
                   WHERE tenant_id = $1 AND job_id = $2
                   ORDER BY step_index ASC"#,
            )
            .bind(*tenant_id)
            .bind(*job_id)
            .fetch_all(&mut *conn)
            .await
            .unwrap_or_default();
            rows.into_iter()
                .filter_map(|r| {
                    Some(VerificationStep {
                        step: r.try_get("step_label").ok()?,
                        detail: r.try_get("detail").ok(),
                        ts: r.try_get("step_ts").ok()?,
                    })
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_fixed_when_blocked_and_healthy() {
        // baseline exploitable, exploit now 403, app healthy ⇒ Fixed
        assert_eq!(classify_verdict(true, 403, true), HealVerdict::Fixed);
        // 3xx redirect away from the vulnerable success also counts as fixed
        assert_eq!(classify_verdict(true, 302, true), HealVerdict::Fixed);
        assert_eq!(classify_verdict(true, 404, true), HealVerdict::Fixed);
    }

    #[test]
    fn verdict_broke_app_when_5xx_or_unhealthy() {
        // exploit route now 500 ⇒ the patch crashed it, not a valid fix
        assert_eq!(classify_verdict(true, 500, true), HealVerdict::BrokeApp);
        // connection refused / no response ⇒ BrokeApp
        assert_eq!(classify_verdict(true, 0, true), HealVerdict::BrokeApp);
        // exploit blocked (403) but the health probe failed ⇒ app is down ⇒ BrokeApp
        assert_eq!(classify_verdict(true, 403, false), HealVerdict::BrokeApp);
    }

    #[test]
    fn verdict_still_vulnerable_when_2xx() {
        assert_eq!(
            classify_verdict(true, 200, true),
            HealVerdict::StillVulnerable
        );
        assert_eq!(
            classify_verdict(true, 299, true),
            HealVerdict::StillVulnerable
        );
    }

    #[test]
    fn verdict_inconclusive_when_baseline_unproven() {
        assert_eq!(
            classify_verdict(false, 403, true),
            HealVerdict::Inconclusive
        );
    }

    #[test]
    fn verdict_as_str_roundtrip() {
        assert_eq!(HealVerdict::Fixed.as_str(), "fixed");
        assert_eq!(HealVerdict::BrokeApp.as_str(), "broke_app");
        assert_eq!(HealVerdict::StillVulnerable.as_str(), "still_vulnerable");
        assert_eq!(HealVerdict::Inconclusive.as_str(), "inconclusive");
    }

    #[test]
    fn tail_chars_returns_suffix() {
        assert_eq!(tail_chars("abcdef", 3), "def");
        assert_eq!(tail_chars("ab", 5), "ab");
        assert_eq!(tail_chars("", 3), "");
    }

    #[test]
    fn detect_test_command_by_manifest() {
        let d1 = tempfile::tempdir().unwrap();
        std::fs::write(d1.path().join("Cargo.toml"), "[package]\n").unwrap();
        assert!(detect_test_command(d1.path())
            .unwrap()
            .last()
            .unwrap()
            .contains("cargo test"));

        let d2 = tempfile::tempdir().unwrap();
        std::fs::write(
            d2.path().join("package.json"),
            r#"{"scripts":{"test":"jest"}}"#,
        )
        .unwrap();
        assert!(detect_test_command(d2.path())
            .unwrap()
            .last()
            .unwrap()
            .contains("npm test"));

        // package.json with the npm default placeholder is NOT a runnable test.
        let d3 = tempfile::tempdir().unwrap();
        std::fs::write(
            d3.path().join("package.json"),
            r#"{"scripts":{"test":"echo \"Error: no test specified\" && exit 1"}}"#,
        )
        .unwrap();
        assert!(detect_test_command(d3.path()).is_none());

        // empty repo → no gate.
        let d4 = tempfile::tempdir().unwrap();
        assert!(detect_test_command(d4.path()).is_none());
    }

    #[tokio::test]
    async fn collect_changed_files_reads_applied_content() {
        // Build a throwaway git repo, commit a baseline, modify + add files, and assert the
        // collector returns the post-change content (this is what gets committed to the PR).
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return, // no tempdir in this environment; skip
        };
        let repo = dir.path();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(args)
                .output()
        };
        if run(&["init", "-q"]).is_err() {
            return; // git not available in test env; skip
        }
        let _ = run(&["config", "user.email", "t@t.io"]);
        let _ = run(&["config", "user.name", "t"]);
        std::fs::write(repo.join("app.js"), "const x = eval(req.body);\n").unwrap();
        let _ = run(&["add", "-A"]);
        let _ = run(&["commit", "-q", "-m", "base"]);
        // Apply the "fix": modify app.js and add a new file.
        std::fs::write(repo.join("app.js"), "const x = JSON.parse(req.body);\n").unwrap();
        std::fs::write(repo.join("SECURITY.md"), "hardened\n").unwrap();

        let (files, deleted) = collect_changed_files(repo).await.expect("collect");
        assert!(deleted.is_empty());
        let map: std::collections::HashMap<_, _> = files.into_iter().collect();
        assert_eq!(
            map.get("app.js").map(String::as_str),
            Some("const x = JSON.parse(req.body);\n")
        );
        assert_eq!(
            map.get("SECURITY.md").map(String::as_str),
            Some("hardened\n")
        );
    }

    #[tokio::test]
    async fn collect_changed_files_errors_on_no_change() {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        };
        let repo = dir.path();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(args)
                .output()
        };
        if run(&["init", "-q"]).is_err() {
            return;
        }
        let _ = run(&["config", "user.email", "t@t.io"]);
        let _ = run(&["config", "user.name", "t"]);
        std::fs::write(repo.join("a.txt"), "x\n").unwrap();
        let _ = run(&["add", "-A"]);
        let _ = run(&["commit", "-q", "-m", "base"]);
        // No change applied ⇒ collector must fail loudly (never open an empty PR).
        assert!(collect_changed_files(repo).await.is_err());
    }
}
