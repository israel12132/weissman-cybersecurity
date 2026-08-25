//! Load `.env` from predictable locations and validate `DATABASE_URL`.
//!
//! When `DATABASE_URL` is missing or has no `user@` segment, libpq defaults to the **OS username**
//! (e.g. `root` under systemd), which breaks production Postgres roles (`postgres`, `weissman_app`, …).

use std::path::Path;

fn env_truthy(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Set by a launcher that has already resolved the whole configuration itself
/// (`start_weissman.sh`): env files may then only FILL gaps, never contradict the process.
///
/// Without it, `PORT=9999 ./start_weissman.sh` bound :8000 anyway — the launcher honoured the
/// caller, then this loader replayed `PORT=8000` from the repo `.env` on top of it.
fn process_env_wins() -> bool {
    env_truthy("WEISSMAN_ENV_PROCESS_WINS")
}

/// Apply env-file entries on top of the process environment.
///
/// A **blank** entry is not a value — it is a key the operator left for someone else to fill —
/// so it is ignored completely: it neither erases what is already set nor defines the variable
/// as empty. `PRODUCTION.env.template`, and therefore every `.env` copied from it, ships
/// `DATABASE_URL=`, `REDIS_URL=`, `WEISSMAN_MIGRATE_URL=` and `WEISSMAN_AUTH_DATABASE_URL=`
/// blank on purpose, because Compose supplies them per container. Treating those as real values
/// is what made `DATABASE_URL=postgres://… ./start_weissman.sh` die with "DATABASE_URL is not
/// set", and what turned a blank `WEISSMAN_AUTH_DATABASE_URL` into an empty DSN instead of the
/// documented fallback to `DATABASE_URL`.
fn apply_entries<I>(entries: I)
where
    I: IntoIterator<Item = Result<(String, String), dotenvy::Error>>,
{
    let fill_only = process_env_wins();
    for (key, value) in entries.into_iter().flatten() {
        if value.trim().is_empty() {
            continue;
        }
        if fill_only && std::env::var(&key).is_ok_and(|v| !v.trim().is_empty()) {
            continue;
        }
        std::env::set_var(key, value);
    }
}

fn apply_env_file(path: &Path) {
    if let Ok(entries) = dotenvy::from_path_iter(path) {
        apply_entries(entries);
    }
}

/// Load environment files so `DATABASE_URL` is set even when `WorkingDirectory` is not the repo root.
/// Later sources override earlier ones (explicit production paths win), and `WEISSMAN_ENV_FILE`
/// is applied last so it can override them all — the precedence the manuals document.
pub fn load_process_environment() {
    // E2E / CI local stack: never load repo `.env` (often production) over explicit dev exports.
    let e2e_stack = env_truthy("WEISSMAN_E2E_STACK");

    if !e2e_stack {
        // dotenvy's own search (cwd upwards). Applied through apply_entries rather than
        // `dotenv()` so it obeys the same blank-is-not-a-value rule as every file below.
        if let Ok(entries) = dotenvy::dotenv_iter() {
            apply_entries(entries);
        }

        if let Ok(cwd) = std::env::current_dir() {
            let p = cwd.join(".env");
            if p.is_file() {
                apply_env_file(&p);
            }
        }

        if let Ok(mut p) = std::env::current_dir() {
            if p.pop() {
                let env = p.join(".env");
                if env.is_file() {
                    apply_env_file(&env);
                }
            }
        }

        // Common absolute deploy path (systemd WorkingDirectory often not the git checkout).
        let deploy = Path::new("/root/weissman-bot/.env");
        if deploy.is_file() {
            apply_env_file(deploy);
        }
    }

    // Last, so an operator-chosen file actually wins over the implicit ones above.
    if let Ok(p) = std::env::var("WEISSMAN_ENV_FILE") {
        let path = Path::new(p.trim());
        if path.is_file() {
            apply_env_file(path);
        }
    }

    if e2e_stack {
        return;
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
    use std::io::Write;

    /// `WEISSMAN_ENV_PROCESS_WINS` is process-global, so the tests that toggle it must not
    /// overlap with each other.
    static PROCESS_WINS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "weissman-env-bootstrap-{}-{:?}.env",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut f = std::fs::File::create(&path).expect("create temp env file");
        f.write_all(contents.as_bytes()).expect("write temp env file");
        path
    }

    #[test]
    fn blank_entry_never_erases_an_exported_value() {
        // PRODUCTION.env.template ships DATABASE_URL= blank (Compose fills it per container).
        // Replaying that over a bare-metal export is what made `DATABASE_URL=… ./start_weissman.sh`
        // fail with "DATABASE_URL is not set".
        let key = "WEISSMAN_TEST_EB_BLANK";
        std::env::set_var(key, "postgres://u:p@127.0.0.1:5432/weissman");
        let path = env_file(&format!("{key}=\n"));
        apply_env_file(&path);
        assert_eq!(
            std::env::var(key).as_deref(),
            Ok("postgres://u:p@127.0.0.1:5432/weissman")
        );
        std::env::remove_var(key);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn blank_entry_leaves_the_key_unset_rather_than_empty() {
        // "Unset" and "set to empty string" are the same to `unwrap_or_default()` but opposite
        // to `unwrap_or_else(fallback)`: a blank WEISSMAN_AUTH_DATABASE_URL used to reach
        // connect_pools as an empty DSN instead of falling back to DATABASE_URL.
        let key = "WEISSMAN_TEST_EB_FILL_BLANK";
        std::env::remove_var(key);
        let path = env_file(&format!("{key}=\n"));
        apply_env_file(&path);
        assert!(std::env::var(key).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn real_value_overrides_by_default() {
        let _guard = PROCESS_WINS_LOCK.lock().expect("env lock poisoned");
        std::env::remove_var("WEISSMAN_ENV_PROCESS_WINS");
        let key = "WEISSMAN_TEST_EB_OVERRIDE";
        std::env::set_var(key, "from-process");
        let path = env_file(&format!("{key}=from-file\n"));
        apply_env_file(&path);
        assert_eq!(std::env::var(key).as_deref(), Ok("from-file"));
        std::env::remove_var(key);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn process_env_wins_keeps_the_launcher_resolved_value() {
        let _guard = PROCESS_WINS_LOCK.lock().expect("env lock poisoned");
        let key = "WEISSMAN_TEST_EB_PROCESS_WINS";
        let unset = "WEISSMAN_TEST_EB_PROCESS_WINS_GAP";
        std::env::set_var("WEISSMAN_ENV_PROCESS_WINS", "1");
        std::env::set_var(key, "resolved-by-launcher");
        std::env::remove_var(unset);
        let path = env_file(&format!("{key}=from-file\n{unset}=from-file\n"));
        // Occupied keys survive; gaps are still filled from the file.
        apply_env_file(&path);
        assert_eq!(std::env::var(key).as_deref(), Ok("resolved-by-launcher"));
        assert_eq!(std::env::var(unset).as_deref(), Ok("from-file"));
        std::env::remove_var("WEISSMAN_ENV_PROCESS_WINS");
        std::env::remove_var(key);
        std::env::remove_var(unset);
        let _ = std::fs::remove_file(path);
    }

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
}
