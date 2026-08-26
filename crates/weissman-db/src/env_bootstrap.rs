//! Load `.env` from predictable locations and validate `DATABASE_URL`.
//!
//! When `DATABASE_URL` is missing or has no `user@` segment, libpq defaults to the **OS username**
//! (e.g. `root` under systemd), which breaks production Postgres roles (`postgres`, `weissman_app`, …).

use std::path::Path;

/// Load environment files so `DATABASE_URL` is set even when `WorkingDirectory` is not the repo root.
/// Later sources override earlier ones (explicit production paths win).
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
        apply_compose_dsn_fallbacks();
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

    apply_compose_dsn_fallbacks();
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

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// RFC 3986 unreserved — safe in URI userinfo without percent-encoding.
fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode a URI userinfo password so `+` `/` in launcher secrets cannot
/// be parsed as space or as the path separator.
pub fn percent_encode_userinfo(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for &b in raw.as_bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn password_userinfo_needs_encode(pass: &str) -> bool {
    pass.bytes()
        .any(|b| matches!(b, b'+' | b'/' | b' ' | b'@' | b'?' | b'#' | b'[' | b']'))
}

/// Re-encode the password in `scheme://user:password@host/...` when it contains
/// characters that break URI parsers. Returns `None` when no change is needed.
pub fn reencode_url_password(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let at = rest.rfind('@')?;
    let userinfo = &rest[..at];
    let host = &rest[at + 1..];
    let (user, pass) = userinfo.split_once(':')?;
    if pass.is_empty() || !password_userinfo_needs_encode(pass) {
        return None;
    }
    Some(format!(
        "{scheme}://{user}:{}@{host}",
        percent_encode_userinfo(pass)
    ))
}

fn postgres_url(user: &str, password: &str, host: &str, db: &str) -> String {
    format!(
        "postgresql://{}:{}@{host}:5432/{db}",
        percent_encode_userinfo(user),
        percent_encode_userinfo(password)
    )
}

fn dsn_unusable(url: Option<&str>) -> bool {
    match url.map(str::trim).filter(|s| !s.is_empty()) {
        None => true,
        Some(u) => validate_database_url(u).is_err(),
    }
}

/// Compose `env_file` can inject empty `DATABASE_URL=` / `REDIS_URL=` lines from
/// `PRODUCTION.env.template`. Rebuild from discrete password pieces, then
/// percent-encode `+` in existing URLs so role AUTH matches `requirepass`.
pub fn apply_compose_dsn_fallbacks() {
    let host = nonempty_env("WEISSMAN_DB_HOST").unwrap_or_else(|| "postgres".into());
    let db = nonempty_env("POSTGRES_DB").unwrap_or_else(|| "weissman".into());

    if dsn_unusable(std::env::var("DATABASE_URL").ok().as_deref()) {
        if let Some(pass) = nonempty_env("DB_APP_PASSWORD") {
            let user = nonempty_env("DB_APP_USER").unwrap_or_else(|| "weissman_app".into());
            std::env::set_var("DATABASE_URL", postgres_url(&user, &pass, &host, &db));
        }
    }
    if dsn_unusable(std::env::var("WEISSMAN_AUTH_DATABASE_URL").ok().as_deref()) {
        if let Some(pass) = nonempty_env("DB_AUTH_PASSWORD") {
            let user = nonempty_env("DB_AUTH_USER").unwrap_or_else(|| "weissman_auth".into());
            std::env::set_var(
                "WEISSMAN_AUTH_DATABASE_URL",
                postgres_url(&user, &pass, &host, &db),
            );
        }
    }
    if dsn_unusable(
        std::env::var("WEISSMAN_READ_ONLY_DATABASE_URL")
            .ok()
            .as_deref(),
    ) {
        if let Some(pass) = nonempty_env("DB_RO_PASSWORD") {
            let user = nonempty_env("DB_RO_USER").unwrap_or_else(|| "weissman_ro".into());
            std::env::set_var(
                "WEISSMAN_READ_ONLY_DATABASE_URL",
                postgres_url(&user, &pass, &host, &db),
            );
        }
    }
    if dsn_unusable(std::env::var("WEISSMAN_MIGRATE_URL").ok().as_deref()) {
        if let Some(pass) = nonempty_env("POSTGRES_PASSWORD") {
            let user = nonempty_env("POSTGRES_USER").unwrap_or_else(|| "postgres".into());
            std::env::set_var(
                "WEISSMAN_MIGRATE_URL",
                postgres_url(&user, &pass, &host, &db),
            );
        }
    }
    if std::env::var("REDIS_URL")
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
    {
        if let Some(pass) = nonempty_env("REDIS_PASSWORD") {
            let rhost = nonempty_env("WEISSMAN_REDIS_HOST").unwrap_or_else(|| "redis".into());
            std::env::set_var(
                "REDIS_URL",
                format!("redis://:{}@{rhost}:6379/0", percent_encode_userinfo(&pass)),
            );
        }
    }

    for var in [
        "DATABASE_URL",
        "WEISSMAN_AUTH_DATABASE_URL",
        "WEISSMAN_READ_ONLY_DATABASE_URL",
        "WEISSMAN_MIGRATE_URL",
        "REDIS_URL",
    ] {
        if let Ok(url) = std::env::var(var) {
            if let Some(fixed) = reencode_url_password(&url) {
                std::env::set_var(var, fixed);
            }
        }
    }
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

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env(pairs: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _g = ENV_LOCK.lock().expect("env lock");
        let prev: Vec<(String, Option<String>)> = pairs
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in pairs {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in prev {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }

    #[test]
    fn encodes_plus_and_equals_once_plus_is_present() {
        let out =
            reencode_url_password("postgresql://weissman_app:abc+def=@postgres:5432/weissman")
                .expect("should re-encode");
        assert_eq!(
            out,
            "postgresql://weissman_app:abc%2Bdef%3D@postgres:5432/weissman"
        );
    }

    #[test]
    fn encodes_redis_password_with_plus() {
        let out = reencode_url_password("redis://:pass+word@redis:6379/0").expect("encode");
        assert_eq!(out, "redis://:pass%2Bword@redis:6379/0");
    }

    #[test]
    fn leaves_url_safe_password_alone() {
        assert!(reencode_url_password(
            "postgresql://weissman_app:hexonlysecret@postgres:5432/weissman"
        )
        .is_none());
    }

    #[test]
    fn rebuilds_empty_database_url_from_compose_pieces() {
        with_env(
            &[
                ("DATABASE_URL", Some("")),
                ("DB_APP_USER", Some("weissman_app")),
                ("DB_APP_PASSWORD", Some("abc+def")),
                ("POSTGRES_DB", Some("weissman")),
                ("WEISSMAN_DB_HOST", Some("postgres")),
                ("REDIS_URL", Some("redis://redis:6379/0")),
                ("WEISSMAN_AUTH_DATABASE_URL", None),
                ("WEISSMAN_READ_ONLY_DATABASE_URL", None),
                ("WEISSMAN_MIGRATE_URL", None),
                ("DB_AUTH_PASSWORD", None),
                ("DB_RO_PASSWORD", None),
                ("POSTGRES_PASSWORD", None),
                ("REDIS_PASSWORD", None),
            ],
            || {
                apply_compose_dsn_fallbacks();
                assert_eq!(
                    std::env::var("DATABASE_URL").unwrap(),
                    "postgresql://weissman_app:abc%2Bdef@postgres:5432/weissman"
                );
            },
        );
    }

    #[test]
    fn rebuilds_empty_redis_url_from_password() {
        with_env(
            &[
                ("REDIS_URL", Some("")),
                ("REDIS_PASSWORD", Some("secret+plus")),
                ("WEISSMAN_REDIS_HOST", Some("redis")),
                (
                    "DATABASE_URL",
                    Some("postgresql://weissman_app:ok@postgres:5432/weissman"),
                ),
                ("WEISSMAN_AUTH_DATABASE_URL", None),
                ("WEISSMAN_READ_ONLY_DATABASE_URL", None),
                ("WEISSMAN_MIGRATE_URL", None),
                ("DB_APP_PASSWORD", None),
                ("DB_AUTH_PASSWORD", None),
                ("DB_RO_PASSWORD", None),
                ("POSTGRES_PASSWORD", None),
            ],
            || {
                apply_compose_dsn_fallbacks();
                assert_eq!(
                    std::env::var("REDIS_URL").unwrap(),
                    "redis://:secret%2Bplus@redis:6379/0"
                );
            },
        );
    }
}
