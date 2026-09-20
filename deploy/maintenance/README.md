# Maintenance page (`deploy/maintenance/`)

**Automatic — no action needed.** Every gateway layer (host nginx / Caddy, Kubernetes
ingress default backend, Cloudflare Worker) serves this page by itself whenever the origin
cannot answer (502 / 504 / connection failure) and stops the moment it answers again. The
page polls `/api/health` and reloads the visitor's original URL on the first genuine 200.
The maintenance *flag* below is an optional extra for announced windows, never a step in a
normal rebuild.

Operator runbook (what visitors see per failure mode, `deploy/rebuild.sh`, announced windows,
Cloudflare, Kubernetes, curl checks, troubleshooting):
`docs/operations/MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD.md` (Hebrew: `…-he.md`).

## What is here

| Path | Role |
|---|---|
| `src/strings.mjs` | **All copy** (EN + HE + Command Center variant), the one contact address (`weissmancybersecurity@gmail.com`), the copyright `YEAR` (build-time constant) |
| `src/template.mjs` | Markup + CSS; `page({ locale, variant, assetBase, fonts, mark })` |
| `src/maintenance.js` | The single CSP-safe external script (health polling, countdown, planned window, RTL/l10n via `data-l10n-*`) |
| `src/logo.svg` | The mark (inlined + `data:` favicon) |
| `src/k8s-default.conf` | nginx `server{}` for the Kubernetes default backend |
| `build.mjs` | Generator (node ≥ 22, zero deps, deterministic) |
| `maintenance-mode.sh` | Optional flag: `on` / `off` / `status` / `is-on` |
| `install.sh` | Build + install `dist/` for a systemd host gateway |
| `state/` | Runtime state (`maintenance.on`, `status.json`) — git-ignored |

## Build

```
node deploy/maintenance/build.mjs           # write everything
node deploy/maintenance/build.mjs --check   # CI: exit 1 on drift
```

Generated (never hand-edit): `dist/index.html`, `dist/he/index.html`, `dist/maintenance.js`,
`dist/api.json`, `dist/status.example.json`, `frontend/public/offline.html` (Command Center
variant), `deploy/cloudflare/maintenance-worker/assets.generated.mjs`,
`deploy/k8s/maintenance-page-configmap.yaml`. Fonts are inlined from `deploy/public/fonts`.

## Where each layer reads it

- **Docker Compose gateway** — `deploy/frontend.Dockerfile` COPYs `dist/` into the image at
  `/usr/share/nginx/html/maintenance`; `docker-compose.yml` bind-mounts the host state dir
  (`${WEISSMAN_MAINTENANCE_STATE_DIR:-./deploy/maintenance/state}`) read-only at
  `/var/lib/weissman/maintenance`. Same routing and headers as the host layer below.
- **Host nginx / Caddy** — `install.sh` copies `dist/` to `/opt/weissman/maintenance`
  (`WEISSMAN_MAINTENANCE_ROOT`; state dir `WEISSMAN_MAINTENANCE_STATE_DIR`, default
  `$ROOT/state` = `/opt/weissman/maintenance/state`; `--no-build` only verifies the committed
  dist). The gateway serves it at `/maintenance/` and falls back to it
  on 502/504/connection failure (`/he/…` → `he/index.html`, `Accept: application/json` or
  `/api/*`, `/hooks/*`, `/ws/*`, `/install/*` → `api.json`) with `503` + `Retry-After: 30` + `Cache-Control: no-store` +
  `X-Weissman-Maintenance: 1`. `maintenance.js` itself must be served with **200**.
- **Kubernetes** — `deploy/k8s/maintenance-page-configmap.yaml` (`weissman-maintenance-page`,
  keys `index.html`, `he.html`, `maintenance.js`, `api.json`, `default.conf`) mounted at
  `/usr/share/nginx/html` (+ `default.conf` at `/etc/nginx/conf.d/default.conf`) in an
  `nginxinc/nginx-unprivileged` pod used as the ingress-nginx default backend with
  `custom-http-errors: 502,503,504`. `default.conf` routes on the ingress headers
  `X-Original-URI` / `X-Format` (same JSON prefixes as the gateway), serves the page through a
  URI `error_page` so a POST/PUT/DELETE gets the 503 body rather than nginx's 405, listens on
  IPv4 only, and answers `/healthz` 200 for probes. It runs under
  `scripts/test_maintenance_contract.sh`.
- **Cloudflare Worker** — imports `HTML_EN`, `HTML_HE`, `MAINTENANCE_JS`, `API_JSON` from
  `assets.generated.mjs` and serves them when the origin fails.
- **Command Center** — `frontend/public/offline.html` (`/command-center/offline.html`) is the same
  design in the app's palette, English only, no locale pill. It works when the service worker
  serves it for a navigation: every asset URL is absolute and the page is complete without the
  script.

## Toggle (optional — announced windows only)

```
deploy/maintenance/maintenance-mode.sh on --reason "Database migration" --until 2026-09-27T04:00:00+03:00
deploy/maintenance/maintenance-mode.sh status [--json]
deploy/maintenance/maintenance-mode.sh is-on          # exit 0 = on, 1 = off
deploy/maintenance/maintenance-mode.sh off
```

`on` writes `maintenance.on` + `status.json` (`{"mode":"planned","reason":…,"until":…,"since":…}`)
under `WEISSMAN_MAINTENANCE_STATE_DIR` (default `state/` next to the script; on a VPS pass
`/opt/weissman/maintenance/state`); `off` removes both files. `--until` takes ISO-8601 with an
offset or anything GNU `date -d` parses; a value without an offset (`"2026-09-27 04:00"`) is read
as Israel time (`WEISSMAN_MAINTENANCE_TZ` overrides), not the host's clock, so a UTC VPS does not
announce the wrong hour. While the flag exists, nginx/Caddy answer every request
except `/maintenance/*` with the 503 page even if the app is up; the gateway serves `status.json`
at `/maintenance/status.json` and the page then shows "Planned maintenance", the reason and a
localized "Expected back by" (an ETA already in the past is never shown). `404` is the normal
answer when nothing is announced. Both files are checked per request — no reload. `off` by
default; nothing depends on it. `deploy/rebuild.sh --with-maintenance-flag` raises and clears it
around a rollout.

## Design contract (short)

One `<script defer src="/maintenance/maintenance.js">`, no inline script, `data:` fonts and
favicon, inline SVG — fits `script-src 'self'`. Stable ids: `#maint-live` (`data-state`),
`#maint-state` (the only live region; `aria-live` is switched off while a probe is in flight
and for a repeat of the sentence already announced, so screen readers hear state changes, not
every poll), `#maint-last-checked`, `#maint-countdown`,
`#maint-retry-form` / `#maint-retry`, `#maint-planned` / `#maint-reason` / `#maint-until`;
`html[data-mode=planned]`, `html[data-overdue]`, `html[data-variant]`. Every Latin/numeric token
inside Hebrew text is isolated (`dir="ltr"` / `<bdi>`); the copyright year is baked in at build.
