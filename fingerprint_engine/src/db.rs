//! Re-exports the authoritative Postgres / RLS layer ([`weissman_db`]). Prefer importing `weissman_db`
//! directly in new code; this module keeps `crate::db::` and `fingerprint_engine::db::` stable.

pub use weissman_db::*;
