# Auth DB Password Rotation (Zero Downtime)

Rotate the `weissman_auth` PostgreSQL role password without a maintenance window.

## Prerequisites

- `WEISSMAN_MIGRATE_URL` — postgres superuser (used for boot-time role sync)
- Short-lived maintenance credentials with `ALTER ROLE` on `weissman_auth`
- Rolling restart capability for `weissman-server` and `weissman-worker`

## Environment variables

| Variable | Purpose |
|----------|---------|
| `WEISSMAN_AUTH_DB_ROTATION_URL` | Maintenance connection (superuser) for `ALTER ROLE weissman_auth PASSWORD ...` |
| `WEISSMAN_AUTH_ROTATED_PASSWORD` | New password (≥32 chars) |
| `WEISSMAN_AUTH_DATABASE_URL` | Application DSN used by server/worker after rotation |

Boot-time helpers (always safe to keep set):

| Variable | Purpose |
|----------|---------|
| `WEISSMAN_MIGRATE_URL` | After migrations, `sync_role_passwords_from_env_on_boot()` aligns `weissman_app` / `weissman_auth` passwords from DSNs |

## Procedure

1. **Generate** a strong password:
   ```bash
   openssl rand -base64 48
   ```

2. **Apply** in Postgres (automated):
   ```bash
   export WEISSMAN_AUTH_DB_ROTATION_URL='postgresql://postgres:...@db:5432/weissman'
   export WEISSMAN_AUTH_ROTATED_PASSWORD='...'
   bash scripts/rotate_auth_db_password.sh
   ```

3. **Update** `WEISSMAN_AUTH_DATABASE_URL` in your secret store / `.env.production` with the new password.

4. **Rolling restart** one replica at a time:
   - Restart `weissman-server` → verify `/api/health`
   - Restart `weissman-worker` → verify job consumption

5. **Verify** auth pool connectivity from logs (`auth_rotation` target, no connection errors).

6. **Remove** one-shot rotation vars from deploy config (`WEISSMAN_AUTH_DB_ROTATION_URL`, `WEISSMAN_AUTH_ROTATED_PASSWORD`).

## Docker / compose

On next boot, when `WEISSMAN_MIGRATE_URL` is set, the server runs:

1. `run_migrations`
2. `sync_role_passwords_from_env_on_boot()` — pushes passwords from DSNs to roles
3. `rotate_weissman_auth_password_on_boot()` — applies rotation vars when present

This allows updating only the env file and rolling containers without manual SQL.

## Rollback

If a replica fails to connect after rotation:

1. Revert `WEISSMAN_AUTH_DATABASE_URL` to the previous password on that replica, **or**
2. Re-run rotation with the previous known-good password via maintenance URL.

Never leave `WEISSMAN_AUTH_ROTATED_PASSWORD` in production env after rotation completes.
