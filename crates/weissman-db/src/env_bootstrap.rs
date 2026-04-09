//! Load `.env` from predictable locations and validate `DATABASE_URL`.
//!
//! When `DATABASE_URL` is missing or has no `user@` segment, libpq defaults to the **OS username**
//! (e.g. `root` under systemd), which breaks production Postgres roles (`postgres`, `weissman_app`, …).

use std::path::Path;

/// Load environment files so `DATABASE_URL` is set even when `WorkingDirectory` is not the repo root.
/// Later sources override earlier ones (explicit production paths win).
pub fn load_process_environment() {
    let _ = dotenvy::dotenv();

    if let Ok(p) = std::env::var("WEISSMAN_ENV_FILE") {
        let path = Path::new(p.trim());
        if path.is_file() {
            let _ = dotenvy::from_path_override(path);
        }
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
        assert!(validate_database_url("postgres://postgres:secret@localhost/weissman_prod").is_ok());
    }
}
