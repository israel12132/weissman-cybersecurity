# Runbook — Continuity Page & Zero-Downtime Rebuild

English original; Hebrew counterpart: [`MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD-he.md`](MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD-he.md).
Keep the two in sync when either changes.

> **Automatic — nothing to switch on.** Whenever the origin cannot answer (the backend is
> restarting, rebuilding, migrating, or the whole machine is off), every layer in front of it
> serves the branded Weissman page as **HTTP 503 + `Retry-After: 30`** instead of a browser,
> nginx or Cloudflare error. The page re-checks `/api/health` and returns the visitor to the URL
> they asked for on the first genuine 200. It disappears by itself. No flag, no reload, no step
> in the rebuild.
>
> To ship new code: `deploy/rebuild.sh` (§2). The maintenance *flag* (§3) is an optional extra
> for announced windows only.

Generator, sources and the layer contract: `deploy/maintenance/README.md`.
The page's only contact address is **weissmancybersecurity@gmail.com** (assistance and security
reports alike); it also links to `/status`.

---

## 1. What the visitor sees, and which layer serves it

| Situation | Layer that answers | What the visitor sees | Way back |
|-----------|--------------------|-----------------------|----------|
| Backend restarting, migrating (~90 s), crashed, or recreated (`systemctl restart`, `docker compose up`) | Docker gateway nginx (`deploy/nginx-gateway.conf`), VPS nginx (`deploy/nginx-weissman.conf`) or Caddy (`deploy/Caddyfile`): their own 502/504 become the page | The branded 503 page on the **first** failed request — a stopped process refuses the connection instantly; a half-alive listener is bounded by `proxy_connect_timeout 5s` / `dial_timeout 5s` | The page polls `/api/health` (5 s → 60 s backoff); the first genuine 200 reloads the original URL |
| Rebuild with `deploy/rebuild.sh` (§2) | Same as above; the gateway keeps its listener open while backend/worker are recreated or the units restart | Same page; the script prints how long the origin was unreachable | Same |
| Cold start / host reboot (Compose) | Gateway starts with `depends_on: backend: condition: service_started`, so it listens **before** the backend is healthy | The page during the backend's migrations instead of "connection refused" | Same |
| Whole machine off, unplugged, unreachable | **Cloudflare Worker** (`deploy/cloudflare/maintenance-worker/`, proxied DNS only) — the only layer that can answer when the host is gone | The same page from Cloudflare's edge (also `/he`, `api.json`, the script) instead of Cloudflare's 521/522 | The Worker passes the origin through as soon as it answers; the page reloads on the first 200 |
| Kubernetes: gateway rollout, node drain, `kubectl scale deploy/weissman-gateway --replicas=0`, gateway 502/503/504 | ingress-nginx default backend `weissman-maintenance` (§5) | The page instead of ingress-nginx's bare "502 Bad Gateway" | Gateway endpoints Ready again |
| Announced window (**optional**, §3): `maintenance-mode.sh on` | nginx gateway / VPS nginx / Caddy read the flag file per request; Cloudflare reads `MAINTENANCE_MODE` | The page **even while the app is up**, with the eyebrow "Planned maintenance", the reason and "Expected back by" | `maintenance-mode.sh off` (no reload) |
| Command Center open during any of the above | The SPA itself: both API clients detect the branded 503 and raise the in-app overlay; the service worker serves `/command-center/offline.html` for navigations | "Command Center is being updated." overlay with last-checked time, countdown and *Retry now* | A genuine 200 from `/api/health` closes the overlay and refetches the active queries |

What "the page" is, in every layer:

- **English** at any path, **Hebrew** (`lang="he" dir="rtl"`) under `/he`, each linking to the
  other; eyebrow *Scheduled update*, headline *A platform update is in progress.* / *מתבצע עדכון
  מערכת.*, the assurance that data, scheduled scans and queued jobs are preserved, a live
  *Last checked / Next check* card, *Check again*, *Status updates* → `/status`, the standard
  window (Sundays 02:00–04:00 Israel time) and the contact address. "Any path" means every
  path that reaches the backend. On the **Docker gateway** the marketing pages (`/`, `/he/`,
  `/pricing`…) and the Command Center shell are static files in the image and keep serving
  from disk (200) while the backend is away; there the page appears at `/status`, as
  `api.json` on `/api/*`, `/ws/*`, `/hooks/*`, `/install/*`, and inside the Command Center
  (overlay + `offline.html`) — `/` and `/he/` become the 503 page only with the flag (§3). On
  **VPS nginx and Caddy** everything is proxied, so every path, `/` and `/he/` included, gets
  the page.
- **`api.json`** for machines — `/api/*`, `/hooks/*`, `/ws/*`, `/install/*` (nginx and the Cloudflare Worker alike), or any
  request whose `Accept` contains `application/json`; a POST/PUT/DELETE at the Cloudflare layer:

  ```json
  {
    "status": "maintenance",
    "code": 503,
    "message": "Scheduled platform update in progress; service resumes automatically.",
    "retry_after_seconds": 30,
    "contact": "weissmancybersecurity@gmail.com",
    "status_page": "/status"
  }
  ```

- **Headers on every 503**: `Retry-After: 30`, `Cache-Control: no-store`,
  `X-Weissman-Maintenance: 1`, `X-Robots-Tag: noindex, nofollow`, plus the security headers.
  Monitors record a temporary failure (not a fake 200), crawlers keep the real pages indexed,
  caches never keep a copy, and the layers in front (Worker, SPA) read the header as "already
  branded — pass through".
- **`/maintenance/maintenance.js`** is always a genuine **200** (a browser refuses to run a
  script that arrives as 5xx). It polls `GET /api/health` with `cache: 'no-store'` and no
  credentials, backoff 5 s → 60 s (×1.6, ±20 % jitter), counts only a 200 **without**
  `X-Weissman-Maintenance` and not `text/html` as "back" (a branded 503 from our own edge or an
  archived copy never triggers a reload), refuses to reload twice within 15 s (flapping origin),
  and reads `/maintenance/status.json` every 4th check (404 = nothing announced). With
  JavaScript off, `<noscript><meta http-equiv="refresh" content="30">` does the same job.
- An application 503 (e.g. `POST /api/public/demo-request` without SMTP) is **never** replaced
  by the page on nginx/Caddy — only the proxy's own 502/504 are. Cloudflare and ingress-nginx
  cannot tell the two apart; there the status is kept and only the body becomes `api.json`.

---

## 2. Rebuilding without a visible outage — `deploy/rebuild.sh`

**The page is automatic. Nothing is switched on before a rebuild and nothing is switched off
after it.** The script's job is to do the smallest thing that puts new code in front of visitors,
keep the gateway listening throughout, wait for a genuine 200, and tell you how long the origin
was actually away (the window the page covered).

```bash
deploy/rebuild.sh --dry-run      # print the plan for this host, run nothing
deploy/rebuild.sh                # auto-detect compose vs systemd and roll out
```

```
deploy/rebuild.sh [--mode compose|systemd] [--dry-run] [--with-maintenance-flag] [--timeout N]
```

| Option / variable | Meaning |
|-------------------|---------|
| `--mode compose\|systemd` | Force the topology. Default: compose when `docker-compose.yml` exists, `docker` is present and the stack is running; else systemd when `weissman-server.service` is installed |
| `--dry-run` | Print the numbered plan and exit 0 |
| `--timeout N` | Seconds to wait for `/api/health` → 200 (default 300) |
| `--with-maintenance-flag` / `WEISSMAN_REBUILD_MAINTENANCE_FLAG=1` | **Opt-in**: also announce the window (§3). The page appears either way; this only adds the "Planned maintenance" wording. Cleared on every exit path — success, failure, Ctrl+C |
| `WEISSMAN_HEALTH_URL` | Override the URL polled for 200 |
| `WEISSMAN_MAINTENANCE_STATE_DIR` | Where the flag lives (only with the flag). Compose: the directory the gateway bind-mounts (`.env`, default `deploy/maintenance/state`); systemd: `/opt/weissman/maintenance/state` |
| `WEISSMAN_GATEWAY_BIND` / `WEISSMAN_GATEWAY_PORT` | Compose: published gateway address (read from `.env`; `0.0.0.0` is probed as `127.0.0.1`) |
| `WEISSMAN_SKIP_FRONTEND_BUILD=1` | systemd: skip the Command Center build |
| `INSTALL_ROOT` | systemd: install root (default `/opt/weissman/app`) |
| `WEISSMAN_MAINTENANCE_ROOT` | systemd: where the installed page is refreshed (default `/opt/weissman/maintenance`) |

Exit codes: 0 ok, 1 failure (the site keeps serving the page until the origin is back), 2 usage.

### 2.1 Docker Compose

```bash
deploy/rebuild.sh --mode compose
```

1. `docker compose build` — the slow part; the running stack keeps serving.
2. Migration guard: the new backend image must ship every `crates/weissman-db/migrations/*.sql`
   of the checkout, otherwise the run aborts **before** anything is recreated (a crash-looping
   backend is the one thing the page cannot fix).
3. Recreate the **gateway** with `--no-deps` — only if its image id changed (see 2.3), and
   first, so the new gateway is the one covering the backend window.
4. Recreate `backend worker` (+ `worker-soar` only when it already runs, with `--profile soar`)
   with `--no-deps --no-build`. The gateway stays up and answers 503 + page meanwhile.
5. Poll `http://${WEISSMAN_GATEWAY_BIND:-127.0.0.1}:${WEISSMAN_GATEWAY_PORT:-80}/api/health`
   once a second until 200. A crash loop (≥ 3 restarts / exited) fails fast with the container
   log. If the backend container is healthy but the gateway still cannot reach it after 10 s,
   one graceful `docker compose exec -T gateway nginx -s reload` re-resolves the backend
   address (nginx resolves `backend` once at startup).
6. Summary — for example:

```
[rebuild] Rollout finished in 3m 12s — http://127.0.0.1:80/api/health answers 200
[rebuild] Restarted: backend worker
[rebuild] Origin unreachable for 41s — the continuity page covered that window automatically
[rebuild] Maintenance flag: not used (the page is automatic; --with-maintenance-flag announces a window)
```

The compose files and project name are taken from the running containers' labels, so a stack
started without the prod overlay is not recreated with it.

### 2.2 systemd / VPS

```bash
deploy/rebuild.sh --mode systemd
```

1. `cargo build --release -p weissman-server -p weissman-worker` — the running units keep serving.
2. Command Center `npm run build` in `frontend/` (skip: `WEISSMAN_SKIP_FRONTEND_BUILD=1`).
3. `sudo install` the binaries → `/opt/weissman/app/bin`, `rsync` `frontend/dist`.
4. Refresh the installed page: `sudo deploy/maintenance/install.sh --no-build` → `/opt/weissman/maintenance`
   (only when that directory exists; non-fatal).
5. `sudo systemctl restart weissman-server weissman-worker` — from this instant nginx/Caddy
   serve the page.
6. Poll `http://127.0.0.1:${PORT:-8000}/api/health` until 200 (a `failed`/`inactive` unit dies
   fast with the journal).
7. Summary as above.

A non-default server port must be exported (`PORT=…` or `WEISSMAN_HEALTH_URL=…`):
`/etc/weissman/weissman.env` is root-only and is not read.

`./start_weissman.sh --systemd` (the full "start everything" launcher) now does the same wait
after its restart and prints `origin unreachable for N s`; `WEISSMAN_HEALTH_TIMEOUT` (default
300) bounds it. Prefer `deploy/rebuild.sh` for routine rollouts.

### 2.3 What still causes a 1–3 s blip, and how Cloudflare covers it

- **Gateway image changed (Compose).** Recreating the gateway container closes the published
  listener for ~1–2 s; no page on this host can cover a refused connection. `rebuild.sh` skips
  the gateway whenever its image id is unchanged (the common case: backend-only changes) and
  says `Gateway image changed — recreating gateway (--no-deps)` when it must.
- **Cloudflare in front.** For proxied hostnames the Worker (§4) turns that refused connection
  (`fetch()` throws / 52x) into the same branded page, so even the gateway recreate is covered.
- **VPS nginx/Caddy** reloads are graceful (`nginx -s reload`, `systemctl reload caddy`): the
  listener never closes.
- A visitor already on the page during the blip simply sees a missed probe; the next one
  succeeds.

---

## 3. Optional: announced maintenance windows (off by default)

**Not required for anything above.** The flag exists only to *announce* a window: the page then
reads *Planned maintenance*, shows *What is being updated* and a localized *Expected back by*
(Israel time + UTC), and — on nginx/Caddy — is served even while the app is still up (a
migration that must not take writes, a DB switch-over). Per SLA §2, a planned window announced
**≥ 72 hours in advance** does not count against availability — announce it by e-mail and on
`/status` first; the flag is the on-the-day signal.

```
deploy/maintenance/maintenance-mode.sh on [--reason TEXT] [--until ISO-8601]   # announce
deploy/maintenance/maintenance-mode.sh status [--json]                          # show (exit 0)
deploy/maintenance/maintenance-mode.sh is-on                                    # exit 0 on, 1 off
deploy/maintenance/maintenance-mode.sh off                                      # clear
```

`on` writes `maintenance.on` and `status.json`
(`{"mode":"planned","reason":…,"until":…,"since":…}`) into the state directory; `off` removes
both files. `--until` accepts ISO-8601 with an offset (`2026-09-27T04:00:00+03:00`) or anything
GNU `date -d` parses (`"2026-09-27 04:00"`). A value **without** an offset is read as **Israel
time**, not the host's clock — a VPS usually runs on UTC, and `04:00` read there would be
announced as "07:00 Israel time" — so the two forms above are the same instant (override with
`WEISSMAN_MAINTENANCE_TZ=<zone>`; needs `tzdata`); the script prints the stored value, offset
included. An ETA already in the past is never shown. Both files are evaluated per request — no
nginx/Caddy reload for `on` or `off`.

| Topology | State directory (`WEISSMAN_MAINTENANCE_STATE_DIR`) | Command |
|----------|-----------------------------------------------------|---------|
| Docker Compose | `deploy/maintenance/state` in the checkout (the script's default `./state`), bind-mounted **read-only** into the gateway at `/var/lib/weissman/maintenance` — override with `WEISSMAN_MAINTENANCE_STATE_DIR` in `.env`; the directory must exist before `docker compose up` | `deploy/maintenance/maintenance-mode.sh on --reason "Database migration" --until 2026-09-27T04:00:00+03:00` |
| VPS nginx / Caddy | `/opt/weissman/maintenance/state` (created by `install.sh`, root-owned unless `WEISSMAN_MAINTENANCE_OWNER` was given) | `sudo WEISSMAN_MAINTENANCE_STATE_DIR=/opt/weissman/maintenance/state deploy/maintenance/maintenance-mode.sh on --reason "…" --until "…"` |
| Cloudflare Worker | Independent of the host: `npx wrangler deploy --var MAINTENANCE_MODE:on --var MAINTENANCE_REASON:"…" --var MAINTENANCE_UNTIL:2026-09-27T04:00:00+03:00`; a plain `npx wrangler deploy` ends it | see `deploy/cloudflare/maintenance-worker/README.md` |
| Kubernetes | Not read on this layer — the default backend answers 404 for `status.json`; use the Cloudflare variables or the announcement channels | — |

While the flag is up: `/` → 503 English page, `/he/` → 503 Hebrew page, `/api/*` → 503
`api.json`, `/maintenance/*` assets → 200, `/maintenance/status.json` → 200 with the file.

With a rebuild: `deploy/rebuild.sh --with-maintenance-flag` raises the flag right before the
backend recreate/restart (`--reason "Platform update in progress"`), clears it as soon as the
backend is healthy (Compose: container health; systemd: the origin's own 200), and a trap clears
it on any failure or Ctrl+C — the site can never be left announced by the script. The same
opt-in exists in `./start_weissman.sh --systemd` via `WEISSMAN_REBUILD_MAINTENANCE_FLAG=1`.

---

## 4. Cloudflare Worker (the machine-off case)

Full setup, plan limits and caveats: `deploy/cloudflare/maintenance-worker/README.md`. In short:

1. DNS records for the public hostnames **proxied** (orange cloud) — a grey-cloud host never
   reaches a Worker.
2. `cd deploy/cloudflare/maintenance-worker && npx wrangler login`.
3. Set the `routes` in `wrangler.toml` to the real zone (placeholders: `weissman.io/*`,
   `www.weissman.io/*`; nginx/k8s use `weissmancyber.com`).
4. `node deploy/maintenance/build.mjs --check` from the repo root (the assets it bundles are
   generated), then `npx wrangler deploy`.
5. Dashboard → the Worker → Settings → Triggers → route → Failure mode **Fail open**.

Behaviour: healthy answers pass through as the origin's own `Response`; a `fetch()` exception or
an origin status in {502, 503, 504, 520–526, 530} **without** `X-Weissman-Maintenance` becomes the
page (503 + the same headers); with the header it is passed through (a layer behind already
branded it). Non-GET/HEAD → `api.json`; `Upgrade` (WebSocket) requests are never intercepted.
Redeploy after every change to the page. The Workers Free plan (100 k requests/day, pass-through
included) is enough for the site; set the route to fail open.

---

## 5. Kubernetes

Manifests (all in `deploy/k8s/`):

| File | Object |
|------|--------|
| `maintenance-page-configmap.yaml` | ConfigMap `weissman-maintenance-page` — **generated** by `build.mjs`; keys `index.html`, `he.html`, `maintenance.js`, `api.json`, `default.conf` |
| `maintenance-deployment.yaml` | Deployment `weissman-maintenance` (2 replicas, `nginxinc/nginx-unprivileged:1.29-alpine`, read-only root, UID 101, `/healthz:8080` probes), Service `weissman-maintenance` (80 → 8080), PodDisruptionBudget `minAvailable: 1` |
| `network-policies.yaml` | `allow-ingress-to-maintenance` — any namespace → pod port 8080 |
| `ingress.yaml` | `nginx.ingress.kubernetes.io/custom-http-errors: "502,503,504"` + `nginx.ingress.kubernetes.io/default-backend: weissman-maintenance` |

Apply order matters — ingress-nginx only honours a custom default backend that already has
endpoints:

```bash
kubectl -n weissman apply -f deploy/k8s/maintenance-page-configmap.yaml
kubectl -n weissman apply -f deploy/k8s/maintenance-deployment.yaml
kubectl -n weissman rollout status deploy/weissman-maintenance
kubectl -n weissman apply -f deploy/k8s/network-policies.yaml
kubectl -n weissman apply -f deploy/k8s/ingress.yaml
```

How it triggers (both automatic):

1. The gateway Service has no ready endpoints (rollout, drain, scale to 0) → ingress-nginx
   sends the request straight to `weissman-maintenance` with the original URI.
2. The gateway answers 502/503/504 → `custom-http-errors` re-issues the request to the default
   backend with path `/` and headers `X-Code`, `X-Format` (the Accept header), `X-Original-URI`,
   and the **original method**; `default.conf` routes `/he*` → Hebrew, `/api/*`, `/hooks/*`,
   `/ws/*`, `/install/*` or `application/json` → `api.json`, else English, and reaches the page
   through a URI `error_page` so a POST/PUT/DELETE gets the 503 body too (a named location would
   keep the method and nginx's static handler would answer its own 405 — measured).

Manual "gateway down" (e.g. a risky change): `kubectl -n weissman scale deploy/weissman-gateway --replicas=0`
→ every visitor gets the page; `… --replicas=2` brings the site back. No flag is involved.

Verification without touching production traffic:

```bash
kubectl -n weissman port-forward svc/weissman-maintenance 8080:80 &
curl -si localhost:8080/ | head -1                                 # HTTP/1.1 503 …, English page
curl -si -H 'X-Original-URI: /he/' localhost:8080/ | grep -o '<html[^>]*>'   # lang="he" dir="rtl"
curl -si -H 'X-Format: application/json' localhost:8080/ | grep -i content-type  # application/json
curl -si -X POST -H 'X-Original-URI: /api/login' localhost:8080/ | grep -iE '^(HTTP|content-type)'  # 503, application/json (not 405)
curl -si -X DELETE -H 'X-Original-URI: /he/x' localhost:8080/ | head -1   # HTTP/1.1 503 …, Hebrew page (not 405)
curl -si -H 'X-Original-URI: /hooks/paddle' localhost:8080/ | grep -i content-type   # application/json
curl -si localhost:8080/healthz | head -1                          # HTTP/1.1 200 OK
```

The same `default.conf` runs under `scripts/test_maintenance_contract.sh` (§6), so these cases
are also asserted in CI.

Notes: set `limit-req-status-code: "429"` and `limit-conn-status-code: "429"` in the ingress-nginx
controller ConfigMap, otherwise edge rate-limit rejections (503 by default) are shown as the
update page. `default.conf` listens on IPv4 only (`listen 8080`), like the gateway pod's nginx:
the image's default `listen [::]:8080` makes nginx probe an IPv6 socket at config test, and on a
node with `ipv6.disable=1` the pod crash-loops before serving a page. An IPv6-only cluster adds
that line back in `deploy/maintenance/src/k8s-default.conf` and rebuilds.

---

## 6. Verification

Run these before merging a change to any of the layers (the gate for this feature):

| Command | Expect |
|---------|--------|
| `node deploy/maintenance/build.mjs --check` | `build.mjs --check: all generated files are up to date`, exit 0 (exit 1 lists drifted files → run `node deploy/maintenance/build.mjs` and commit) |
| `bash scripts/test_maintenance_contract.sh` | `Maintenance contract: 311 passed, 0 failed`, exit 0. Docker-free: the real `nginx-gateway.conf`, `nginx-weissman.conf` and the Kubernetes `default.conf` under a local nginx on `127.0.0.1:18080–18085` against a dead and a stub upstream, flag on/off, JSON/Hebrew routing, request methods, normalised paths, headers exactly once. Needs `nginx`, `curl`, `openssl` — on Ubuntu 24.04 `nginx-light` is enough (it is what CI installs: the same binary minus dynamic modules); on 22.04 install `nginx-full`, whose `nginx-light` lacks `limit_req`/`limit_conn`/`realip`. Prints `SKIP: nginx unavailable` and exits 0 without nginx. `KEEP=1` keeps the work dir |
| `node --test deploy/cloudflare/maintenance-worker/worker.test.mjs` | `# pass 38`, `# fail 0` (Node 22 runs a bare directory as one file — name the file or use the glob `'deploy/cloudflare/maintenance-worker/*.test.mjs'`) |
| `caddy validate --config deploy/Caddyfile --adapter caddyfile` | `Valid configuration` |
| `deploy/rebuild.sh --dry-run` | The numbered plan for this host; `maintenance flag: not used — opt in with --with-maintenance-flag …` |

Live check on a host (Compose shown; on a VPS use `https://<host>` and
`sudo systemctl stop weissman-server`). On the Docker gateway check a **proxied** URL: `/` there
is the static marketing site served from the image and stays 200 with the backend away (§1);
on VPS nginx / Caddy everything is proxied and `https://<host>/` shows the same headers.

```bash
docker compose stop backend                       # or: sudo systemctl stop weissman-server
curl -si http://127.0.0.1/status | grep -iE '^(HTTP|content-type|retry-after|cache-control|x-weissman-maintenance|x-robots-tag)'
```

```
HTTP/1.1 503 Service Temporarily Unavailable
Content-Type: text/html; charset=utf-8
Retry-After: 30
Cache-Control: no-store
X-Weissman-Maintenance: 1
X-Robots-Tag: noindex, nofollow
```

```bash
curl -si http://127.0.0.1/api/health | grep -iE '^(HTTP|content-type)'   # 503, application/json
curl -s  http://127.0.0.1/api/health                            # the api.json body from §1
curl -si -X POST http://127.0.0.1/api/login | head -1           # 503 api.json (not 405)
curl -si http://127.0.0.1/ | head -1                            # Compose: 200 — the static marketing page (§1)
curl -s  https://<host>/he/ | grep -o '<html[^>]*>'             # VPS nginx / Caddy: <html lang="he" dir="rtl" …> (Compose: only with the flag, §3)
curl -sI http://127.0.0.1/maintenance/maintenance.js | grep -iE '^(HTTP|content-type)'  # 200, javascript
curl -si http://127.0.0.1/maintenance/status.json | head -1     # 404 (nothing announced)
curl -si https://<host>/maintenance/state/maintenance.on | head -1   # VPS nginx / Caddy: 404 — the state dir is never served
docker compose start backend                                    # or: sudo systemctl start weissman-server
curl -si http://127.0.0.1/api/health | grep -iE '^(HTTP|x-weissman)'    # 200, no maintenance header
```

Through Cloudflare (the Worker's README has the full list): `curl -sI https://<host>/` with the
origin stopped → `503`, `x-weissman-maintenance: 1`, `retry-after: 30`; `/maintenance/maintenance.js` → `200`.

Command Center: open `/command-center/`, stop the backend — the overlay appears within one
failed request and closes by itself after the backend is back (no manual reload).

---

## 7. Troubleshooting — "the page is not showing"

Work down the list; each row is one `curl` away.

| Symptom | Check | Fix |
|---------|-------|-----|
| Browser "can't connect" / `curl: (7)` on the host itself | Is the gateway process up? Compose: `docker compose ps gateway`; VPS: `systemctl status nginx` / `systemctl status caddy` | The page needs a listener. Start the gateway; on Compose the gateway no longer waits for a healthy backend (`service_started`). Only the Cloudflare Worker (§4) covers a host with nothing listening |
| Cloudflare 521/522/523 page | Worker deployed and routed? DNS proxied (orange cloud)? Route pattern = the real hostname? | `npx wrangler deploy` from `deploy/cloudflare/maintenance-worker/`; fix `routes` in `wrangler.toml`; proxy the record. Also set Failure mode "Fail open" |
| nginx's own grey "503 Service Temporarily Unavailable" (no headers, no branding) on a VPS | `ls /opt/weissman/maintenance/index.html` | Page not installed: `node deploy/maintenance/build.mjs && sudo deploy/maintenance/install.sh`. Then `sudo nginx -t && sudo systemctl reload nginx` |
| Caddy answers an empty 502 that *does* carry `X-Weissman-Maintenance: 1` | Same — the headers are set before `file_server` fails | Install the page as above (`/opt/weissman/maintenance`), `sudo systemctl reload caddy` |
| Bare nginx 502 instead of the page on a VPS | Is the shipped `deploy/nginx-weissman.conf` the one in `/etc/nginx/sites-enabled/`? `sudo nginx -t` | Re-copy the conf (its header has the install lines), `sudo nginx -t && sudo systemctl reload nginx`. The `volatile` map needs nginx ≥ 1.11.7 |
| Page shows but is unstyled, no countdown / no clock | `curl -sI …/maintenance/maintenance.js` must be **200** with a JavaScript content type | The assets location is missing or the script is answered 5xx. On Compose the file is baked into the image (`deploy/frontend.Dockerfile`), rebuild the gateway image; on a VPS reinstall the page |
| Page shows but never goes away although the app is up | `deploy/maintenance/maintenance-mode.sh status` — is the flag on? Does the origin itself answer 200? Compose: `docker compose ps backend` (healthy) or `docker compose exec backend curl -sf http://localhost:8000/api/health`; VPS: `curl -si http://127.0.0.1:8000/api/health` | Flag on → `… off`. Origin 200 but gateway still 503 (Compose): nginx cached the old backend address → `docker compose exec -T gateway nginx -s reload` (`rebuild.sh` does this by itself after 10 s). A 200 counts only without `X-Weissman-Maintenance` and not `text/html` |
| `/maintenance/status.json` is 404 although the flag is on | Which state dir did `maintenance-mode.sh` write to? `status` prints it | Must be the directory the gateway reads: Compose `${WEISSMAN_MAINTENANCE_STATE_DIR:-./deploy/maintenance/state}` (bind-mounted at `/var/lib/weissman/maintenance`), VPS `/opt/weissman/maintenance/state` — pass `WEISSMAN_MAINTENANCE_STATE_DIR` accordingly |
| Compose: `maintenance-mode.sh on` fails with permission denied | State dir set outside the checkout and created by Docker (root-owned) | Create the directory yourself before `docker compose up`, or run `install.sh` with `WEISSMAN_MAINTENANCE_OWNER=user:group` |
| An API 503 is answered with the app's own JSON, not `api.json` | Is it an application 503 (`POST /api/public/demo-request` without SMTP)? | By design on nginx/Caddy: only the proxy's own 502/504 become the page. Cloudflare/ingress-nginx replace the body only, status kept |
| Kubernetes: ingress-nginx's own error page | `kubectl -n weissman get endpoints weissman-maintenance` — empty? Applied in the wrong order? Pod crash-looping (`kubectl -n weissman logs deploy/weissman-maintenance`; an IPv6-only cluster needs `listen [::]:8080` added back, §5)? | Apply ConfigMap → Deployment → wait `rollout status` → Ingress (§5). The controller logs an error and uses its global default backend while the Service has no endpoints |
| Kubernetes: throttled clients see the update page | `limit-rps` / `limit-connections` rejections are 503 by default | `limit-req-status-code: "429"`, `limit-conn-status-code: "429"` in the controller ConfigMap |
| `build.mjs --check` fails in CI | Someone edited a generated file, or the sources changed without a rebuild | `node deploy/maintenance/build.mjs`, commit the outputs. The copyright year is the literal `YEAR` in `deploy/maintenance/src/strings.mjs` — bump it by hand each January |
| Uptime monitor pages during a rebuild | It sees the 503 | Expected and intended (Retry-After 30). Key the monitor on `X-Weissman-Maintenance: 1` to classify it as maintenance rather than an outage |
| Command Center: raw error toasts instead of the overlay | Is the response branded? With no gateway at all (local dev, backend off) `fetch` rejects and there is nothing to detect | Overlay only reacts to a branded 502/503/504 by design; navigations still get `offline.html` from the service worker once it has been installed |

---

## Files

| Path | Role |
|------|------|
| `deploy/maintenance/` | Generator (`build.mjs`), sources (`src/`), outputs (`dist/`), `maintenance-mode.sh`, `install.sh`, `state/` — see its README |
| `deploy/rebuild.sh` | Zero-downtime rollout (Compose + systemd) |
| `deploy/nginx-gateway.conf`, `deploy/frontend.Dockerfile`, `docker-compose.yml` | Compose gateway: page at `/usr/share/nginx/html/maintenance` in the image, state bind-mounted read-only at `/var/lib/weissman/maintenance` |
| `deploy/nginx-weissman.conf`, `deploy/Caddyfile` | VPS: page `/opt/weissman/maintenance`, state `/opt/weissman/maintenance/state` |
| `deploy/cloudflare/maintenance-worker/` | Edge Worker (`wrangler.toml`, `src/worker.mjs`, `worker.test.mjs`, README) |
| `deploy/k8s/maintenance-*.yaml`, `ingress.yaml`, `network-policies.yaml` | Kubernetes default backend |
| `frontend/public/offline.html`, `frontend/public/tactical-chunk-sw.js`, `frontend/src/components/Maintenance*.jsx` | Command Center variant, service worker fallback, in-app overlay |
| `scripts/test_maintenance_contract.sh` | Docker-free contract suite for both nginx configs |
| `SLA_AND_STATUS.md` §5, §8 | Customer-facing commitment (503 + Retry-After; 72 h notice for planned windows) |
