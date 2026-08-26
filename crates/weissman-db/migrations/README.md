# Database migrations — Weissman PostgreSQL schema

## Canonical tree

**Authoritative migrations:** `crates/weissman-db/migrations/`

The runtime migrator (`weissman-db`, started via `WEISSMAN_MIGRATE_URL` on boot) reads SQL from
`WEISSMAN_MIGRATIONS_DIR` (Docker: `/srv/migrations`) **and** embeds the same tree at compile
time via `sqlx::migrate!("./migrations")`. A version that exists in Postgres `_sqlx_migrations`
but not in this directory makes the live backend refuse to start (`VersionMissing`).

## Mirror tree (CI sync only)

`fingerprint_engine/migrations/` is a **byte-synced mirror** of the canonical tree. It exists so
engine developers colocated with `fingerprint_engine` see schema changes in context.

**Never edit only one side.** After adding or changing a migration:

```bash
bash scripts/check-migration-sync.sh   # must exit 0 before merge
```

The script compares filenames and SQL bodies (comments stripped). Comment-only diffs are allowed.

## Roles applied by migrations

| Role | Purpose |
|------|---------|
| `weissman_app` | Application pool — subject to RLS (`app.current_tenant_id`) |
| `weissman_auth` | Login / IdP plane — BYPASSRLS for credential lookup |
| `weissman_ro` | Ask Weissman NL→SQL — SELECT-only, statement timeout |

## Ordering

Filenames use UTC timestamps (`YYYYMMDDHHMMSS_description.sql`). The custom no-tx pre-runner
executes extension/role/bootstrap files before the sqlx transaction batch.
