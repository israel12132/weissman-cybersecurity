# Weissman production (systemd)

## What runs

| Unit | Role |
|------|------|
| `weissman-server` | Axum API, orchestrator hooks, **serves React from `frontend/dist`** (no separate Node/PM2 service). |
| `weissman-worker` | Claims and runs `weissman_async_jobs` (**required** for Engine Room “Run”, tenant scans, PoE, etc.). |
| `weissman.target` | Groups the stack for `systemctl start weissman.target`. |

There is **no** `weissman-frontend` process: build once with `npm run build` and deploy `frontend/dist` under `WorkingDirectory` (default `/opt/weissman/app/frontend/dist`), or set `WEISSMAN_STATIC` in `/etc/weissman/weissman.env`.

## One-shot install

From the repo root (as root):

```bash
sudo bash deploy/systemd/install-weissman-systemd.sh
```

Edit secrets:

```bash
sudo chmod 600 /etc/weissman/weissman.env
sudo nano /etc/weissman/weissman.env   # DATABASE_URL, WEISSMAN_JWT_SECRET, WEISSMAN_COOKIE_SECURE=1, PORT, …
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now weissman-server weissman-worker weissman.target
```

## Logs

```bash
journalctl -u weissman-server -f
journalctl -u weissman-worker -f
journalctl -u weissman-server -u weissman-worker --since today
```

## PostgreSQL on the same VM

Install Postgres, create DB/users, then either:

- Add to both units: `After=postgresql.service` and `Requires=postgresql.service`, **or**
- Use `Wants=postgresql.service` (so boot continues if Postgres is down).

Example override:

```bash
sudo systemctl edit weissman-server
```

```ini
[Unit]
After=postgresql.service
Requires=postgresql.service
```

## Reboot behaviour

With `enable --now`, systemd starts services after `network-online.target`. Both units use `Restart=always`.

## Environment file

All production variables live in `/etc/weissman/weissman.env` (mode `600`). See `weissman.env.example` and repo `.env.example`.

## Non-default install path

```bash
sudo INSTALL_ROOT=/srv/weissman/app bash deploy/systemd/install-weissman-systemd.sh
```

The script rewrites `WorkingDirectory` and `ExecStart` paths in the unit files via `sed`.

## Reverse proxy (nginx / Caddy) and the continuity page

`weissman-server` listens on `127.0.0.1:$PORT` only; `deploy/nginx-weissman.conf` (with
`deploy/nginx-snippet-websocket-map.conf` copied to `/etc/nginx/conf.d/00-websocket-map.conf`) or
`deploy/Caddyfile` terminates TLS in front of it. Both files carry their install lines in the header.

Both configs also serve the branded **continuity page — automatically, nothing to switch on**:
whenever the units cannot answer (a `systemctl restart`, the ~90 s of migrations at boot, a crash,
a rebuild) the proxy's own 502/504 become the Weissman page as HTTP 503 + `Retry-After: 30`,
and the page reloads the visitor's original URL the moment `/api/health` answers 200 again.
The page must be on disk for that:

```bash
sudo bash deploy/maintenance/install.sh      # dist → /opt/weissman/maintenance, state → /opt/weissman/maintenance/state
```

`install-weissman-systemd.sh` runs `deploy/maintenance/install.sh --no-build` for you (non-fatal;
if it reports the committed dist as stale run `node deploy/maintenance/build.mjs && sudo deploy/maintenance/install.sh`).

Rollouts: `deploy/rebuild.sh` (build → install → restart units → wait for `/api/health` 200 →
how long the origin was unreachable). Announced windows are optional:
`sudo WEISSMAN_MAINTENANCE_STATE_DIR=/opt/weissman/maintenance/state deploy/maintenance/maintenance-mode.sh on --reason "…" --until "…"`
(`… off` ends it; no reload needed). Full runbook, curl checks and troubleshooting:
`docs/operations/MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD.md`.

## Hetzner checklist

1. Postgres running and `DATABASE_URL` with explicit `user:pass@host` (see `weissman_db::validate_database_url`).
2. `WEISSMAN_JWT_SECRET` set.
3. HTTPS reverse proxy (Caddy/nginx) → `127.0.0.1:$PORT`; set `WEISSMAN_COOKIE_SECURE=1` and `WEISSMAN_PUBLIC_BASE_URL`.
4. Firewall: only 80/443 public; DB not exposed publicly unless required.
