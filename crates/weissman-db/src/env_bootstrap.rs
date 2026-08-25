//! Load `.env` from predictable locations and validate `DATABASE_URL`.
//!
//! When `DATABASE_URL` is missing or has no `user@` segment, libpq defaults to the **OS username**
//! (e.g. `root` under systemd), which breaks production Postgres roles (`postgres`, `weissman_app`, …).

use std::path::Path;

/// Compiled max-power capability profile (`deploy/env.max-power.env`). No secrets.
const COMPILED_MAX_POWER_ENV: &str = include_str!("../../../deploy/env.max-power.env");

/// Load environment files so `DATABASE_URL` is set even when `WorkingDirectory` is not the repo root.
/// Later sources override earlier ones (explicit production paths win).
///
/// After files are loaded, the compiled max-power capability profile is applied so a `git pull`
/// + rebuild + restart turns Genesis/Council/fuzz/crons on at full strength without a separate
/// env-edit step. Secrets (JWT, DB, OpenAI keys) stay in `.env` — they are not in the fragment.
/// Skip with `WEISSMAN_MAX_POWER=0`, `WEISSMAN_E2E_STACK=1`, or CI (`CI` / `GITHUB_ACTIONS`).
pub fn load_process_environment() {
    // E2E / CI local stack: never load repo `.env` (often production) over explicit dev exports.
    let e2e_stack = std::env::var("WEISSMAN_E2E_STACK")
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes"));

    if !e2e_stack {
        let _ = dotenvy::dotenv();
    }

    if let Ok(p) = std::env::var("WEISSMAN_ENV_FILE") {
        let path = Path::new(p.trim());
        if path.is_file() {
            let _ = dotenvy::from_path_override(path);
        }
    }

    if e2e_stack {
        return;
    }

    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join(".env");
        if p.is_file() {
            let _ = dotenvy::from_path_override(&p);
        }
    }

    if let Ok(mut p) = std::env::current_dir() {
        if p.pop() {
            let env = p.join(".env");
            if env.is_file() {
                let _ = dotenvy::from_path_override(&env);
            }
        }
    }

    // Common absolute deploy path (systemd WorkingDirectory often not the git checkout).
    let deploy = Path::new("/root/weissman-bot/.env");
    if deploy.is_file() {
        let _ = dotenvy::from_path_override(deploy);
    }

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

    apply_compiled_max_power_profile();
}

fn env_flag_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Parse `KEY=value` lines from a dotenv-style fragment (comments and blanks skipped).
pub fn parse_env_fragment(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter_map(|line| {
            let s = line.trim();
            if s.is_empty() || s.starts_with('#') {
                return None;
            }
            let (k, v) = s.split_once('=')?;
            let k = k.trim();
            if k.is_empty() {
                None
            } else {
                Some((k, v.trim()))
            }
        })
        .collect()
}

fn skip_compiled_max_power() -> bool {
    env_flag_truthy("WEISSMAN_E2E_STACK")
        || env_flag_truthy("CI")
        || env_flag_truthy("GITHUB_ACTIONS")
        || matches!(
            std::env::var("WEISSMAN_MAX_POWER")
                .ok()
                .as_deref()
                .map(str::trim)
                .map(|s| s.to_ascii_lowercase())
                .as_deref(),
            Some("0") | Some("false") | Some("no") | Some("off")
        )
}

/// Overlay compiled capability flags (not secrets) so the binary itself is max-power.
fn apply_compiled_max_power_profile() {
    if skip_compiled_max_power() {
        return;
    }
    let pairs = parse_env_fragment(COMPILED_MAX_POWER_ENV);
    for (k, v) in &pairs {
        std::env::set_var(k, v);
    }
    eprintln!(
        "[Weissman] compiled max-power profile applied ({} keys). Set WEISSMAN_MAX_POWER=0 to skip.",
        pairs.len()
    );
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
    fn compiled_max_power_fragment_is_live_only_and_complete() {
        let pairs = parse_env_fragment(COMPILED_MAX_POWER_ENV);
        assert!(
            pairs.len() >= 100,
            "expected a full capability profile, got {}",
            pairs.len()
        );
        let map: std::collections::HashMap<&str, &str> = pairs.into_iter().collect();
        assert_eq!(map.get("WEISSMAN_GENESIS_PROTOCOL").copied(), Some("1"));
        assert_eq!(map.get("WEISSMAN_SUPREME_COUNCIL").copied(), Some("1"));
        assert_eq!(map.get("WEISSMAN_GENERATIVE_FUZZ").copied(), Some("1"));
        assert_eq!(map.get("WEISSMAN_SELF_IMPROVE").copied(), Some("1"));
        assert_eq!(map.get("WEISSMAN_LLM_MODEL").copied(), Some("gpt-4o"));
        assert_eq!(map.get("WEISSMAN_ADVISORY_FINDINGS").copied(), Some("0"));
        assert_eq!(map.get("WEISSMAN_ALLOW_INSECURE_TLS").copied(), Some("0"));
        assert_eq!(map.get("WEISSMAN_HEAL_AUTO_MERGE").copied(), Some("0"));
        for (k, v) in &map {
            assert!(!v.starts_with("sk-"), "secret leaked in {k}");
            assert!(!k.contains("API_KEY"), "API key must not be compiled in");
        }
    }

    #[test]
    fn parse_env_fragment_skips_comments() {
        let pairs = parse_env_fragment("# hi\nFOO=bar\n\n# x\nBAZ=1\n");
        assert_eq!(pairs, vec![("FOO", "bar"), ("BAZ", "1")]);
    }
}
