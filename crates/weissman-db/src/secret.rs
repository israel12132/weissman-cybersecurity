//! Zeroizing wrappers for connection secrets loaded from the environment.
//!
//! DSNs and passwords must not be cloned into long-lived globals (`OnceLock`,
//! process-wide URL caches). Hold them in these types, use [`SecretUrl::expose`]
//! for the **one** connect call that needs the bytes, then drop so
//! [`ZeroizeOnDrop`] overwrites the heap allocation.
//!
//! The long-lived handle is the SQLx [`sqlx::PgPool`], stored on `AppState` /
//! worker state. A pool does not expose the original DSN as a usable string.
//! Rebuilding a pool on every API request would redo TCP/TLS and Postgres
//! authentication and is forbidden. `OnceLock` is banned for **URL strings**,
//! not for the pool itself.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A database URL (or any connection string) that wipes itself when dropped.
///
/// Not [`Clone`]: cloning would re-materialise the secret on the heap.
///
/// Use only while establishing (or rotating) a [`sqlx::PgPool`]. After
/// `connect` / `connect_lazy` returns, drop this wrapper. Keep the pool.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretUrl {
    inner: String,
}

impl SecretUrl {
    /// Wrap an owned string. The caller must not keep another live copy.
    #[must_use]
    pub fn new(inner: String) -> Self {
        Self { inner }
    }

    /// Borrow the secret for a focused operation (connect, validate). Do not
    /// store the returned slice past this wrapper's lifetime.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Run `f` with the secret and return its result; the wrapper still owns the bytes.
    pub fn with_exposed<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        f(&self.inner)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl std::fmt::Debug for SecretUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretUrl([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_url() {
        let secret = SecretUrl::new("postgres://user:hunter2@127.0.0.1/weissman".into());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretUrl([redacted])");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("postgres"));
    }

    #[test]
    fn expose_and_with_exposed_see_the_same_bytes() {
        let secret = SecretUrl::new("postgres://local/db".into());
        assert_eq!(secret.expose(), "postgres://local/db");
        assert_eq!(secret.with_exposed(|s| s.len()), "postgres://local/db".len());
        assert!(!secret.is_empty());
    }
}
