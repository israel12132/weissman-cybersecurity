//! Full auto-heal round-trip integration tests.
//!
//! These run INSIDE the sandbox with NO Docker daemon for the host-side pipeline (A/B/C):
//!  - (A) real `patch` + `git` apply/collect on a real tempdir repo,
//!  - (B) the real `http_probe` (real reqwest → a real local TCP server) fed into the real
//!        `classify_verdict`, proving the Fixed / StillVulnerable / BrokeApp transitions,
//!  - (C) the `parse_curl_request` round-trip.
//! (D) is the true Docker end-to-end, a strict no-op unless `WEISSMAN_IT_DOCKER=1` + a socket + a
//! fixture image are all present.

use fingerprint_engine::verification_sandbox::{
    apply_unified_patch, classify_verdict, collect_changed_files, http_probe, parse_curl_request,
    rewrite_localhost_url, HealVerdict,
};
use reqwest::header::HeaderMap;
use reqwest::Method;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command as StdCommand;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn tool_present(bin: &str) -> bool {
    StdCommand::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git(repo: &Path, args: &[&str]) {
    let _ = StdCommand::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output();
}

// ─────────────────────────────── (A) git patch/collect ───────────────────────────────

#[tokio::test]
async fn git_patch_apply_and_collect_multifile() {
    if !tool_present("git") || !tool_present("patch") {
        eprintln!("SKIP git_patch_apply_and_collect_multifile: git/patch not available");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path();
    if StdCommand::new("git")
        .arg("-C")
        .arg(repo)
        .arg("init")
        .arg("-q")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("SKIP: git init failed");
        return;
    }
    git(repo, &["config", "user.email", "t@t.io"]);
    git(repo, &["config", "user.name", "t"]);
    git(repo, &["config", "diff.renames", "true"]);

    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(repo.join("legacy")).unwrap();
    std::fs::write(repo.join("src/app.js"), "const x = eval(req.body);\n").unwrap();
    std::fs::write(
        repo.join("src/util.js"),
        "module.exports = { clamp: (n) => Math.max(0, n) };\n",
    )
    .unwrap();
    std::fs::write(repo.join("legacy/old.js"), "// deprecated shim\n").unwrap();
    std::fs::write(repo.join("README.md"), "# demo\n").unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "base"]);

    // Modify app.js, add guard.js, rename util.js -> helper.js (delete+add identical), delete old.js.
    let patch = "\
--- a/src/app.js
+++ b/src/app.js
@@ -1 +1 @@
-const x = eval(req.body);
+const x = JSON.parse(req.body);
--- /dev/null
+++ b/src/guard.js
@@ -0,0 +1 @@
+module.exports = (s) => String(s).slice(0, 256);
--- a/src/util.js
+++ /dev/null
@@ -1 +0,0 @@
-module.exports = { clamp: (n) => Math.max(0, n) };
--- /dev/null
+++ b/src/helper.js
@@ -0,0 +1 @@
+module.exports = { clamp: (n) => Math.max(0, n) };
--- a/legacy/old.js
+++ /dev/null
@@ -1 +0,0 @@
-// deprecated shim
";
    let patch_path = dir.path().join("fix.patch");
    std::fs::write(&patch_path, patch).unwrap();

    let applied = apply_unified_patch(repo, &patch_path).await;
    assert!(applied.is_ok(), "apply failed: {:?}", applied);

    let (files, deleted) = collect_changed_files(repo).await.expect("collect");
    let map: HashMap<_, _> = files.into_iter().collect();

    // The applied fix that the PR would commit:
    assert_eq!(
        map.get("src/app.js").map(String::as_str),
        Some("const x = JSON.parse(req.body);\n"),
        "post-patch app.js content"
    );
    assert_eq!(
        map.get("src/guard.js").map(String::as_str),
        Some("module.exports = (s) => String(s).slice(0, 256);\n")
    );
    // helper.js is captured whether git reports it as a rename destination (R) or a plain add (A).
    assert_eq!(
        map.get("src/helper.js").map(String::as_str),
        Some("module.exports = { clamp: (n) => Math.max(0, n) };\n")
    );
    // README is untouched → never captured.
    assert!(!map.contains_key("README.md"));
    // A hard delete is reported (not committed via the blob-tree path).
    assert!(
        deleted.iter().any(|p| p == "legacy/old.js"),
        "deleted: {:?}",
        deleted
    );
}

#[tokio::test]
async fn git_collect_errors_on_no_change() {
    if !tool_present("git") {
        eprintln!("SKIP: git not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    if StdCommand::new("git")
        .arg("-C")
        .arg(repo)
        .arg("init")
        .arg("-q")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        return;
    }
    git(repo, &["config", "user.email", "t@t.io"]);
    git(repo, &["config", "user.name", "t"]);
    std::fs::write(repo.join("a.txt"), "x\n").unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-q", "-m", "base"]);
    // No change applied ⇒ must fail loudly (never open an empty PR).
    assert!(collect_changed_files(repo).await.is_err());
}

// ─────────────────────────────── (B) probe → verdict ───────────────────────────────

// modes: 0=vulnerable(exploit 200 / health 200), 1=fixed(403 / 200),
//        2=broke5xx(exploit 500 / health 200), 3=healthdown(exploit 403 / health 503)
async fn spawn_probe_server(mode: Arc<AtomicU8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let m = mode.load(Ordering::SeqCst);
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/");
            let (code, reason, body): (u16, &str, &str) = if path.starts_with("/health") {
                if m == 3 {
                    (503, "Service Unavailable", "down")
                } else {
                    (200, "OK", "ok")
                }
            } else {
                match m {
                    0 => (200, "OK", "pwned"),
                    1 => (403, "Forbidden", "blocked"),
                    2 => (500, "Internal Server Error", "boom"),
                    _ => (403, "Forbidden", "blocked"),
                }
            };
            let resp = format!(
                "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    port
}

fn ensure_localhost_no_proxy() {
    // http_probe honors env proxies; keep localhost direct so the tests are portable.
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
}

#[tokio::test]
async fn probe_verdict_fixed() {
    ensure_localhost_no_proxy();
    let mode = Arc::new(AtomicU8::new(0));
    let port = spawn_probe_server(mode.clone()).await;
    let exploit = format!("http://127.0.0.1:{port}/exploit");
    let health = format!("http://127.0.0.1:{port}/health");

    let (baseline, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    assert!((200..300).contains(&baseline), "baseline was {baseline}");

    mode.store(1, Ordering::SeqCst);
    let (after, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    let (h, _) = http_probe(Method::GET, &health, &HeaderMap::new(), None).await;
    assert_eq!(after, 403);
    assert_eq!(h, 200);
    assert_eq!(
        classify_verdict(true, after, (200..400).contains(&h)),
        HealVerdict::Fixed
    );
}

#[tokio::test]
async fn probe_verdict_still_vulnerable() {
    ensure_localhost_no_proxy();
    let mode = Arc::new(AtomicU8::new(0));
    let port = spawn_probe_server(mode).await;
    let exploit = format!("http://127.0.0.1:{port}/exploit");
    let (baseline, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    let (after, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    assert!((200..300).contains(&baseline));
    assert_eq!(after, 200);
    assert_eq!(
        classify_verdict(true, after, true),
        HealVerdict::StillVulnerable
    );
}

#[tokio::test]
async fn probe_verdict_broke_app_5xx() {
    ensure_localhost_no_proxy();
    let mode = Arc::new(AtomicU8::new(0));
    let port = spawn_probe_server(mode.clone()).await;
    let exploit = format!("http://127.0.0.1:{port}/exploit");
    let (baseline, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    assert!((200..300).contains(&baseline));
    mode.store(2, Ordering::SeqCst);
    let (after, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    assert_eq!(after, 500);
    assert_eq!(classify_verdict(true, after, true), HealVerdict::BrokeApp);
}

#[tokio::test]
async fn probe_verdict_broke_app_health_down() {
    ensure_localhost_no_proxy();
    let mode = Arc::new(AtomicU8::new(0));
    let port = spawn_probe_server(mode.clone()).await;
    let exploit = format!("http://127.0.0.1:{port}/exploit");
    let health = format!("http://127.0.0.1:{port}/health");
    let (baseline, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    assert!((200..300).contains(&baseline));
    // Exploit now looks blocked (403) BUT the app health is down (503) — must be BrokeApp.
    mode.store(3, Ordering::SeqCst);
    let (after, _) = http_probe(Method::GET, &exploit, &HeaderMap::new(), None).await;
    let (h, _) = http_probe(Method::GET, &health, &HeaderMap::new(), None).await;
    assert_eq!(after, 403);
    assert_eq!(h, 503);
    assert_eq!(
        classify_verdict(true, after, (200..400).contains(&h)),
        HealVerdict::BrokeApp
    );
}

#[tokio::test]
async fn probe_connection_refused_is_zero() {
    ensure_localhost_no_proxy();
    // Bind then drop → nothing listening on that port.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let (status, _) = http_probe(
        Method::GET,
        &format!("http://127.0.0.1:{port}/exploit"),
        &HeaderMap::new(),
        None,
    )
    .await;
    // A dead endpoint yields 0 (no response), which classify_verdict treats as BrokeApp.
    assert_eq!(status, 0);
    assert_eq!(classify_verdict(true, status, true), HealVerdict::BrokeApp);
}

#[test]
fn rewrite_localhost_url_maps_host_port_and_downgrades() {
    assert_eq!(
        rewrite_localhost_url("http://localhost:3000/exploit?x=1", "127.0.0.1", 55123),
        "http://127.0.0.1:55123/exploit?x=1"
    );
    let s = rewrite_localhost_url("https://api.example.com/a", "127.0.0.1", 8080);
    assert!(s.starts_with("http://127.0.0.1:8080/a"), "got {s}");
}

// ─────────────────────────────── (C) curl parse round-trip ───────────────────────────────

#[test]
fn parse_curl_request_roundtrips() {
    let (m, url, headers, body) =
        parse_curl_request("curl -X POST -H Content-Type:application/json -d {\"user\":\"admin\"} https://t.example.com/api").unwrap();
    assert_eq!(m, Method::POST);
    assert_eq!(url, "https://t.example.com/api");
    assert_eq!(headers.get("content-type").unwrap(), "application/json");
    assert_eq!(body.as_deref(), Some(&b"{\"user\":\"admin\"}"[..]));

    let (m2, url2, h2, b2) = parse_curl_request("curl http://127.0.0.1:8080/health").unwrap();
    assert_eq!(m2, Method::GET);
    assert_eq!(url2, "http://127.0.0.1:8080/health");
    assert!(h2.is_empty());
    assert!(b2.is_none());

    let (m3, _u3, h3, b3) =
        parse_curl_request("curl --request PUT --header X-Token:xyz --data payload=1 https://h/p")
            .unwrap();
    assert_eq!(m3, Method::PUT);
    assert_eq!(h3.get("x-token").unwrap(), "xyz");
    assert_eq!(b3.as_deref(), Some(&b"payload=1"[..]));

    let (m4, u4, _h4, _b4) =
        parse_curl_request("curl -k -X DELETE https://h:9000/item/42").unwrap();
    assert_eq!(m4, Method::DELETE);
    assert_eq!(u4, "https://h:9000/item/42");

    // No URL → error.
    assert!(parse_curl_request("curl -X GET -H A:b").is_err());
}

// ─────────────────────────────── (D) Docker-gated full pipeline ───────────────────────────────

#[tokio::test]
async fn docker_full_roundtrip_verify_patch_ephemeral() {
    // Strictly opt-in: needs WEISSMAN_IT_DOCKER=1 + a real docker socket + a fixture image whose
    // CMD serves the bind-mounted /app. In this sandbox there is no socket → it always no-ops.
    if std::env::var("WEISSMAN_IT_DOCKER").as_deref() != Ok("1") {
        eprintln!("SKIP docker_full_roundtrip: set WEISSMAN_IT_DOCKER=1 to run");
        return;
    }
    let socket = std::env::var("DOCKER_HOST")
        .ok()
        .map(|s| s.trim_start_matches("unix://").to_string())
        .unwrap_or_else(|| "/var/run/docker.sock".to_string());
    if !Path::new(&socket).exists() {
        eprintln!("SKIP docker_full_roundtrip: docker socket {socket} not present");
        return;
    }
    let Ok(image) = std::env::var("WEISSMAN_IT_DOCKER_IMAGE") else {
        eprintln!("SKIP docker_full_roundtrip: set WEISSMAN_IT_DOCKER_IMAGE to a fixture image");
        return;
    };
    let container_port: u16 = std::env::var("WEISSMAN_IT_DOCKER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    // A local bare repo cloned via file:// (no network), whose app serves /exploit (2xx) + /health.
    if !tool_present("git") {
        eprintln!("SKIP: git not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    // The fixture repo/app contents are provided by the operator's image; here we only need a repo
    // that the patch applies against. This is a template — adapt server file + patch to your image.
    let app = std::env::var("WEISSMAN_IT_DOCKER_APPFILE").unwrap_or_else(|_| "server.py".into());
    std::fs::write(work.join(&app), "# vulnerable app placeholder\n").unwrap();
    git(&work, &["init", "-q"]);
    git(&work, &["config", "user.email", "t@t.io"]);
    git(&work, &["config", "user.name", "t"]);
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "base"]);
    let bare = dir.path().join("bare.git");
    let _ = StdCommand::new("git")
        .arg("clone")
        .arg("--bare")
        .arg("-q")
        .arg(&work)
        .arg(&bare)
        .output();
    std::env::set_var(
        "WEISSMAN_VERIFY_CLONE_URL_OVERRIDE",
        format!("file://{}", bare.display()),
    );

    let patch = std::env::var("WEISSMAN_IT_DOCKER_PATCH").unwrap_or_default();
    let poc = std::env::var("WEISSMAN_IT_DOCKER_POC")
        .unwrap_or_else(|_| "curl http://127.0.0.1/exploit".into());
    let health = std::env::var("WEISSMAN_IT_DOCKER_HEALTH")
        .unwrap_or_else(|_| "curl http://127.0.0.1/health".into());

    let vr = fingerprint_engine::verification_sandbox::verify_patch_ephemeral_docker(
        &socket,
        &image,
        container_port,
        "local/fixture",
        "main",
        "x-token",
        "github.com",
        &patch,
        &poc,
        &health,
        Some(fingerprint_engine::verification_sandbox::StepSink::Memory(
            Arc::new(tokio::sync::Mutex::new(Vec::new())),
        )),
    )
    .await;
    std::env::remove_var("WEISSMAN_VERIFY_CLONE_URL_OVERRIDE");

    // The point is the verdict transition + real applied-file capture.
    eprintln!(
        "docker round-trip verdict={} baseline={} after={} health_ok={} files={}",
        vr.verdict.as_str(),
        vr.baseline_status,
        vr.after_patch_status,
        vr.health_after_ok,
        vr.changed_files.len()
    );
    assert!(vr.baseline_was_vulnerable, "baseline exploit should be 2xx");
    assert_eq!(vr.verdict, HealVerdict::Fixed);
    assert!(vr.verified);
    assert!(!vr.changed_files.is_empty());
}
