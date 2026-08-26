//! Load `.env` from predictable locations and validate `DATABASE_URL`.
//!
//! When `DATABASE_URL` is missing or has no `user@` segment, libpq defaults to the **OS username**
//! (e.g. `root` under systemd), which breaks production Postgres roles (`postgres`, `weissman_app`, …).

use std::path::Path;

/// Load environment files so `DATABASE_URL` is set even when `WorkingDirectory` is not the repo root.
/// Later sources override earlier ones (explicit production paths win).
///
/// Empty values are never applied: a Docker-stack `.env` from `start_weissman_live.sh` ships
/// `DATABASE_URL=` (compose injects the URL per-container). Applying that would wipe a URL the
/// process already has — `./start_weissman.sh` sets `WEISSMAN_SKIP_DOTENV=1` as a belt-and-braces
/// guard against the same file flipping `WEISSMAN_ENV` back to production.
pub fn load_process_environment() {
    let e2e_stack = env_flag_truthy("WEISSMAN_E2E_STACK");
    let skip_dotenv = env_flag_truthy("WEISSMAN_SKIP_DOTENV");

    if !e2e_stack && !skip_dotenv {
        if let Ok(cwd) = std::env::current_dir() {
            let p = cwd.join(".env");
            if p.is_file() {
                apply_env_file(&p, false);
            }
        }
    }

    if let Ok(p) = std::env::var("WEISSMAN_ENV_FILE") {
        let path = Path::new(p.trim());
        if path.is_file() {
            apply_env_file(path, true);
        }
    }

    if e2e_stack || skip_dotenv {
        apply_dev_metrics_token();
        return;
    }

    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join(".env");
        if p.is_file() {
            apply_env_file(&p, true);
        }
    }

    if let Ok(mut p) = std::env::current_dir() {
        if p.pop() {
            let env = p.join(".env");
            if env.is_file() {
                apply_env_file(&env, true);
            }
        }
    }

    // Common absolute deploy path (systemd WorkingDirectory often not the git checkout).
    let deploy = Path::new("/root/weissman-bot/.env");
    if deploy.is_file() {
        apply_env_file(deploy, true);
    }

    apply_dev_metrics_token();
}

fn apply_dev_metrics_token() {
    // Dev-only convenience: give the metrics endpoint a token when none is set so local
    // runs work. NEVER in production — a source-committed token would satisfy the
    // WEISSMAN_METRICS_TOKEN startup guard with a publicly-known value, leaving /api/metrics
    // readable by anyone. In production the guard must see the operator's real token (or
    // fail closed).
    if !is_production_env()
        && std::env::var("WEISSMAN_METRICS_TOKEN")
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
    {
        std::env::set_var(
            "WEISSMAN_METRICS_TOKEN",
            "dev-metrics-token-32-bytes-minimum-xx",
        );
    }
}

fn env_flag_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "TRUE" | "YES"))
}

/// Parse dotenv-style assignments. Empty values are dropped so they cannot clobber a
/// caller-supplied `DATABASE_URL` / `REDIS_URL`.
fn parse_env_assignments(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        if key.is_empty()
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || key.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        let val = strip_matching_quotes(val.trim());
        if val.is_empty() {
            continue;
        }
        out.push((key.to_string(), val));
    }
    out
}

fn strip_matching_quotes(val: &str) -> String {
    let bytes = val.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && *bytes.last().unwrap() == b'"')
            || (bytes[0] == b'\'' && *bytes.last().unwrap() == b'\''))
    {
        return val[1..val.len() - 1].to_string();
    }
    val.to_string()
}

fn apply_env_file(path: &Path, override_existing: bool) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for (key, val) in parse_env_assignments(&text) {
        if !override_existing && std::env::var(&key).is_ok() {
            continue;
        }
        std::env::set_var(key, val);
    }
}

/// Production detection mirroring weissman_core::tls_policy::is_production_environment.
/// Duplicated (not imported) because weissman-db does not depend on weissman-core.
fn is_production_env() -> bool {
    [
        "WEISSMAN_ENV",
        "RUST_ENV",
        "NODE_ENV",
        "APP_ENV",
        "RAILS_ENV",
    ]
    .iter()
    .any(|var| {
        std::env::var(var)
            .ok()
            .map(|v| {
                let t = v.trim();
                t.eq_ignore_ascii_case("production") || t.eq_ignore_ascii_case("prod")
            })
            .unwrap_or(false)
    })
}

/// True if the URL has a non-empty userinfo segment before `@`.
fn database_url_has_explicit_user(url: &str) -> bool {
    let rest = if let Some(r) = url.strip_prefix("postgres://") {
        r
    } else if let Some(r) = url.strip_prefix("postgresql://") {
        r
    } else {
        return false;
    };
    let Some(at) = rest.find('@') else {
        return false;
    };
    !rest[..at].is_empty()
}

/// Reject URLs that would make libpq fall back to the OS user (e.g. `root`).
pub fn validate_database_url(url: &str) -> Result<(), String> {
    let t = url.trim();
    if t.is_empty() {
        return Err("DATABASE_URL is empty or unset".into());
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        return Err(
            "URL is HTTP(S); use postgres:// or postgresql:// with user:pass@host (this often happens when LLM/API base URL is pasted into a DB env var by mistake)"
                .into(),
        );
    }
    if !t.starts_with("postgres://") && !t.starts_with("postgresql://") {
        return Err(
            "DATABASE_URL must start with postgres:// or postgresql:// (include user:pass@host)"
                .into(),
        );
    }
    if !database_url_has_explicit_user(t) {
        return Err(
            "DATABASE_URL must include an explicit username before @ (e.g. postgres://postgres:...@host/db); \
             otherwise libpq uses the OS user (often 'root' under systemd)"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_user() {
        assert!(validate_database_url("postgres://localhost/weissman_prod").is_err());
        assert!(validate_database_url("postgresql://127.0.0.1:5432/db").is_err());
    }

    #[test]
    fn rejects_http_mistake() {
        assert!(validate_database_url("http://127.0.0.1").is_err());
    }

    #[test]
    fn accepts_postgres_user() {
        assert!(
            validate_database_url("postgres://postgres:secret@localhost/weissman_prod").is_ok()
        );
    }

    #[test]
    fn parse_skips_empty_database_url() {
        let rows = parse_env_assignments(
            "WEISSMAN_ENV=production\nDATABASE_URL=\nREDIS_URL=\nWEISSMAN_JWT_SECRET=abc\n",
        );
        let keys: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"WEISSMAN_ENV"));
        assert!(keys.contains(&"WEISSMAN_JWT_SECRET"));
        assert!(!keys.contains(&"DATABASE_URL"));
        assert!(!keys.contains(&"REDIS_URL"));
    }

    #[test]
    fn parse_strips_quotes_and_export() {
        let rows = parse_env_assignments("export REDIS_URL=\"redis://127.0.0.1:6379/0\"\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "REDIS_URL");
        assert_eq!(rows[0].1, "redis://127.0.0.1:6379/0");
    }

    #[test]
    fn parse_keeps_base64_padding() {
        let rows = parse_env_assignments("WEISSMAN_JWT_SECRET=abc+def/ghi=\n");
        assert_eq!(rows[0].1, "abc+def/ghi=");
    }
}
