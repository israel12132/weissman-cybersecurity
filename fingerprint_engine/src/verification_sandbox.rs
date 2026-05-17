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
    pub container_id: Option<String>,
    pub baseline_status: u16,
    pub after_patch_status: u16,
    pub baseline_was_vulnerable: bool,
    pub exploit_neutralized: bool,
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
                Err(e) => tracing::error!(target: "verification_sandbox", error = %e, "pool acquire for step log"),
            }
        }
    }
}

fn require_baseline_success() -> bool {
    std::env::var("WEISSMAN_VERIFY_REQUIRE_BEFORE_SUCCESS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
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

fn rewrite_localhost_url(url: &str, host: &str, port: u16) -> String {
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

async fn http_probe(
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
    dest: &Path,
) -> Result<(), String> {
    let url = format!(
        "https://x-access-token:{}@github.com/{}.git",
        token, repo_slug
    );
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

async fn apply_unified_patch(repo_dir: &Path, patch_file: &Path) -> Result<String, String> {
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
    patch_content: &str,
    poc_curl: &str,
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
            container_id: None,
            baseline_status: 0,
            after_patch_status: 0,
            baseline_was_vulnerable: false,
            exploit_neutralized: false,
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

    if let Err(e) = git_clone_shallow(repo_slug, base_branch, git_token, &repo_dir).await {
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

    let host_config = HostConfig {
        binds: Some(vec![mount]),
        port_bindings: Some(port_map),
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
            container_id: Some(id),
            baseline_status,
            after_patch_status: 0,
            baseline_was_vulnerable: false,
            exploit_neutralized: false,
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

    step!("container_restart", None);
    if let Err(e) = docker
        .restart_container(&id, Some(RestartContainerOptions { t: 15 }))
        .await
    {
        cleanup_container(&docker, &id).await;
        return fail(&sink, format!("restart: {}", e)).await;
    }
    tokio::time::sleep(Duration::from_secs(CONTAINER_READY_WAIT_SECS)).await;

    let (after_status, after_body) = http_probe(method, &target_url, &hdrs, body.as_deref()).await;
    step!(
        "exploit_after_patch",
        Some(format!(
            "HTTP {} {}",
            after_status,
            after_body.chars().take(120).collect::<String>()
        ))
    );

    let exploit_neutralized = !(200..=299).contains(&after_status);
    let verified = exploit_neutralized;

    cleanup_container(&docker, &id).await;
    step!(
        if verified { "verified" } else { "failed" },
        Some(if verified {
            "Exploit no longer returns 2xx — PR may be opened".into()
        } else {
            "Exploit still returns success range after patch".into()
        })
    );

    VerificationResult {
        verified,
        container_id: Some(id),
        baseline_status,
        after_patch_status: after_status,
        baseline_was_vulnerable,
        exploit_neutralized,
        error: if verified {
            None
        } else {
            Some("Post-patch response still in 2xx range".into())
        },
        steps: collect_steps_only(&sink).await,
    }
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
        container_id: None,
        baseline_status: 0,
        after_patch_status: 0,
        baseline_was_vulnerable: false,
        exploit_neutralized: false,
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
