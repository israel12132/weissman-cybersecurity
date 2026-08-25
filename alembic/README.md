# ⚠️ DEPRECATED — legacy Python/SQLAlchemy migrations

**Do not use this for the running platform.** The authoritative database schema is
owned by the **Rust sqlx migrations**:

- `crates/weissman-db/migrations/` — **canonical**; compiled into `weissman-server`
  and copied to `/srv/migrations` in the backend image
- `fingerprint_engine/migrations/` — byte-synced **mirror** (CI gate
  `scripts/check-migration-sync.sh`)

These Alembic revisions (`001_initial_postgres`, `002_…`, `003_multi_tenancy`)
describe the **old Python schema** from before the Rust rewrite. They are kept only
for historical reference / data-archaeology on legacy deployments.

## Why this is dangerous

`alembic/env.py` reads the **same `DATABASE_URL`** the production stack uses. Running
`alembic upgrade head` against a sqlx-managed database would apply a conflicting
schema and **diverge or corrupt** it. To prevent that, `env.py` now refuses to run
unless you explicitly opt in:

```bash
# Intentionally running the legacy path (almost never what you want):
WEISSMAN_ALLOW_LEGACY_ALEMBIC=1 DATABASE_URL=postgres://… alembic upgrade head
```

## Adding/altering schema

Create a new SQL migration under `crates/weissman-db/migrations/` **and** copy it to
`fingerprint_engine/migrations/` (same filename, same body). See `docs/operations.md` for the migration runner,
the no-transaction (`CONCURRENTLY`) pre-runner, and RLS conventions.

> Removal of this directory (and the rest of the legacy Python tree under `src/`) is a
> planned cleanup, tracked separately — it is left in place for now to avoid breaking
> the `python-audit` CI job and any archived tooling that still references it.
