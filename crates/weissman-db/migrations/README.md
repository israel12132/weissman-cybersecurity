# Database migrations — Weissman PostgreSQL schema

## Canonical tree

**Authoritative migrations:** `crates/weissman-db/migrations/`

The runtime migrator (`weissman-db`, started via `WEISSMAN_MIGRATE_URL` on boot) reads SQL from
`WEISSMAN_MIGRATIONS_DIR` (Docker: `/srv/migrations`) or this directory in native dev.

## Mirror tree (CI sync only)

`fingerprint_engine/migrations/` is a **byte-synced mirror** of the canonical tree. It exists so
engine developers colocated with `fingerprint_engine` see schema changes in context.

**Never edit only one side.** After adding or changing a migration:

```bash
bash scripts/check-migration-sync.sh   # must exit 0 before merge
```

The script compares filenames and SQL bodies (comments stripped). Comment-only diffs are allowed.

**Never edit a migration that may already be applied.** sqlx records a SHA-384 of the file
in `_sqlx_migrations` and refuses to boot if the bytes change (`migration N was previously
applied but has been modified`). Put new SQL in a new `<timestamp>_<description>.sql` file.
`20260826120000_client_scope_isolation.sql` is frozen at the bytes first shipped in 389751f.
`20260826115900` drops the two INSERT-only risk_graph policies so that frozen file can apply;
`20260826180000` recreates them with a WITH CHECK visibility predicate (never USING).

## Roles applied by migrations

| Role | Purpose |
|------|---------|
| `weissman_app` | Application pool — subject to RLS (`app.current_tenant_id`) |
| `weissman_auth` | Login / IdP plane — BYPASSRLS for credential lookup |
| `weissman_ro` | Ask Weissman NL→SQL — SELECT-only, statement timeout |

## Ordering

Filenames use UTC timestamps (`YYYYMMDDHHMMSS_description.sql`). The custom no-tx pre-runner
executes extension/role/bootstrap files before the sqlx transaction batch.
