# Cloudflare maintenance Worker (`deploy/cloudflare/maintenance-worker/`)

**Automatic — no action needed.** This Worker is the outermost layer of the continuity
page: it runs on Cloudflare's edge in front of the origin and serves the branded Weissman
page whenever the origin cannot answer — including when the whole machine is off. The
nginx / Caddy / Kubernetes layers (`deploy/maintenance/README.md`) can only answer while
the host is up; without this Worker, a switched-off or unreachable origin shows
Cloudflare's own 521/522 error page.

## What it does

Every request to the routed hostnames passes through the Worker:

| Origin answer | Visitor gets |
|---|---|
| Any healthy answer (2xx, 3xx, 4xx, 500, 501 …) | **The origin's Response object, untouched** — nothing buffered, no headers rewritten, streaming and caching as if the Worker were not there |
| 502 / 503 / 504, or Cloudflare's 520–526 / 530 (origin refused, timed out, TLS or DNS failure), **without** `X-Weissman-Maintenance` | The branded page (see the table below) |
| 502 / 503 / 504 **with** `X-Weissman-Maintenance: 1` | Untouched — a layer behind us (nginx / Caddy / ingress) already branded it |
| `fetch()` throws | The branded page |
| Request carries an `Upgrade` header (WebSocket) | Straight `fetch(request)`, never intercepted — a handshake cannot be answered with a page |

The branded answer, decided in this order:

| Request | Answer |
|---|---|
| Any method other than GET / HEAD | `api.json`, **503** (a POST never gets HTML) |
| `GET /maintenance/maintenance.js` | The page's script, **200** (browsers refuse to run a script that arrives as 5xx) |
| `GET /maintenance/status.json` | The announced window, 200 — or **404** = nothing announced |
| `/api/…`, `/hooks/…`, `/ws/…` (no `Upgrade`), `/install/…`, or `Accept: application/json` | `api.json`, **503** — the same prefix set nginx / Caddy / k8s map to JSON, so `curl …/install/agent.sh \| sh` never gets HTML |
| `/he`, `/he/…`, or `Accept-Language` preferring Hebrew (`he`, `iw`) | The Hebrew page, **503** |
| Everything else | The English page, **503** |

Every 503 carries `Retry-After: 30`, `Cache-Control: no-store`, `X-Weissman-Maintenance: 1`,
`X-Robots-Tag: noindex, nofollow`, the usual defence-in-depth headers, and a
`Content-Security-Policy` that permits exactly what the page uses (one same-origin
script, the inline `<style>`, `data:` fonts and favicon, `fetch` to `/api/health`). HEAD
gets the same status and headers with no body. Nothing the Worker generates is ever
cached at the edge.

The page itself polls `/api/health`; the first genuine 200 passes straight through and
the page reloads the visitor's original URL. The way back is automatic too.

`Accept-Language` is honoured in the visitor's order of preference: `he`, `he-IL,en;q=0.8`
and `en;q=0.5,he` get Hebrew; `en-US,en;q=0.9,he;q=0.8` prefers English and gets it.

## Requirements and plan

- The site's DNS records must be **proxied** (orange cloud). A Worker only runs for
  proxied traffic; a "DNS only" (grey cloud) hostname never reaches it and keeps showing
  the browser's own connection error when the origin is off.
- The **Workers Free plan** is enough. At the time of writing it allows **100,000 requests
  per day** (resets at midnight UTC) and 10 ms CPU per request; this Worker spends far
  less than that, because a healthy request is a single `fetch(request)` hand-off. Note
  that *every* request to the routed hostnames counts — pass-through included — so a
  site above ~1.1 requests/second on average needs the paid plan. Confirm the current
  numbers on Cloudflare's Workers limits page.
- Set the route's **Failure mode to "Fail open"** (dashboard → Workers & Pages → the
  Worker → Settings → Triggers → the route). Then an exhausted daily quota or a Worker
  fault falls back to proxying the origin as though the Worker did not exist, instead of
  a Cloudflare error page. The code additionally calls `passThroughOnException()` for the
  same reason.
- Node ≥ 22 and Wrangler (`npx wrangler@latest …` needs nothing installed globally).

## Setup

1. In the Cloudflare dashboard, check that the `A`/`AAAA`/`CNAME` records for the public
   hostnames are proxied (orange cloud).
2. `cd deploy/cloudflare/maintenance-worker && npx wrangler login` — opens a browser once.
3. Edit the `routes` in `wrangler.toml` for the real zone. The placeholders are
   `weissman.io/*` and `www.weissman.io/*` (the website's canonical origin);
   `deploy/nginx-weissman.conf` and `deploy/k8s/ingress.yaml` use `weissmancyber.com` —
   add or replace as appropriate. One route per public hostname.
4. Make sure the bundled assets are current: `node deploy/maintenance/build.mjs --check`
   (from the repo root). `assets.generated.mjs` is generated — never edit it by hand.
5. `npx wrangler deploy` (from this directory). Wrangler bundles `src/worker.mjs` and the
   assets into one script (~100 KB, well under the size limit) and binds the routes.
6. Set the route's Failure mode to "Fail open" (see above).

Redeploy after every change to the page (`node deploy/maintenance/build.mjs`, then
`npx wrangler deploy`).

## Announced windows (optional — off by default)

The page appears by itself whenever the origin cannot answer, so nothing here is required.
`MAINTENANCE_MODE = "on"` is only for announcing a window while the origin may still be
up: every request (except Upgrade handshakes) is answered with the page **without
contacting the origin**, and `MAINTENANCE_REASON` / `MAINTENANCE_UNTIL` feed the
"Planned maintenance" block through `/maintenance/status.json`:

```bash
npx wrangler deploy \
  --var MAINTENANCE_MODE:on \
  --var MAINTENANCE_REASON:"Database migration and gateway rollout" \
  --var MAINTENANCE_UNTIL:2026-09-27T04:00:00+03:00
# … and to end the window, redeploy with the defaults from wrangler.toml:
npx wrangler deploy
```

`MAINTENANCE_UNTIL` is ISO-8601 **with an offset**; an unparsable value is dropped rather
than shown wrong, and an ETA already in the past is never displayed by the page. The
variables can also be changed in the dashboard (the Worker → Settings → Variables)
without a deploy — but the next `wrangler deploy` resets them to the values in
`wrangler.toml`, which is the intended way to switch a window off.

This flag is independent of `deploy/maintenance/maintenance-mode.sh` on the host. A
window announced on the host is passed through unchanged (the host's 503 carries the
header); a window announced here never reaches the host.

## Testing

Unit tests (zero dependencies, the origin is a mocked `fetch`):

```bash
node --test deploy/cloudflare/maintenance-worker/worker.test.mjs
# or:  node --test 'deploy/cloudflare/maintenance-worker/*.test.mjs'
```

Node 22 runs a bare directory argument as a single file, so name the file or use the glob.

Against the live zone, with `H=https://weissman.io`:

```bash
# healthy: the origin's own answers, no maintenance header
curl -sI "$H/"            | grep -i -E '^(HTTP|x-weissman-maintenance)'
curl -s  "$H/api/health"

# now stop the origin (systemctl stop weissman-server, docker compose stop gateway, or
# power the machine off) and repeat — the page, not a Cloudflare error:
curl -si "$H/"            | grep -i -E '^(HTTP|retry-after|cache-control|x-weissman-maintenance|content-type)'
curl -s  "$H/he/"         | grep -o '<html[^>]*>'          # lang="he" dir="rtl"
curl -s  -H 'Accept-Language: he' "$H/" | grep -o '<html[^>]*>'
curl -si "$H/api/health"  | head -1                        # HTTP/2 503 + JSON body
curl -si -X POST "$H/api/login" | grep -i content-type     # application/json, never HTML
curl -sI "$H/dashboard"   | head -1                        # HEAD: headers only
curl -sI "$H/maintenance/maintenance.js" | head -1         # HTTP/2 200 (the page's script)
curl -si "$H/maintenance/status.json" | head -1            # 404 unless a window is announced

# start the origin again: the page's next probe of /api/health sees a genuine 200 and
# reloads the visitor's original URL by itself.
```

A local dry run without deploying: `npx wrangler dev --host weissman.io` serves the
Worker on `localhost:8787` with the real hostname in the request URL, so `fetch(request)`
reaches the real site.

## Caveats

- **Grey-cloud DNS is not covered.** Only proxied hostnames pass through Cloudflare and
  therefore through the Worker.
- **Always Online is not a substitute.** Cloudflare's Always Online serves an Internet
  Archive snapshot of a static page when the origin returns 5xx; it cannot cover the
  Command Center, `/api/*`, POSTs or pages that were never archived, and it shows stale
  content as if it were live. It can stay enabled alongside the Worker for the marketing
  pages if wanted — the page's health probe ignores an archived HTML 200 by design — but
  the Worker is what gives every visitor the branded page.
- **An application 503 without the header is treated as an outage.** The Worker cannot
  tell an application 503 from an infrastructure one, so a 503 the app itself returns
  (e.g. `POST /api/public/demo-request` when SMTP is not configured) is answered with
  `api.json` instead — same status, different body. The website's demo form only checks
  the status and falls back to its mailto link, so it keeps working. The same trade-off is
  documented for the Kubernetes default backend.
- **Everything counts against the request quota**, healthy pass-through included (see
  the plan notes above). Set the route to fail open.
- **Errors before the Worker runs are not covered**: a WAF block, a Cloudflare 1xxx
  error, or a Cloudflare outage happens before any Worker executes.
- **WebSocket handshakes during an outage still fail** at the client (they are handed to
  the origin unchanged). The Command Center's own maintenance overlay covers that case.
- Cloudflare may keep serving cached static assets from its cache while the origin is
  down; that is harmless and shortens the page's visible time.
- `compatibility_date` in `wrangler.toml` pins the runtime behaviour; a Wrangler older
  than that date refuses to deploy — use `npx wrangler@latest`.

## Files

| File | Role |
|---|---|
| `wrangler.toml` | Worker name, entry point, zone routes, default variables (`MAINTENANCE_MODE = "off"`) |
| `src/worker.mjs` | The Worker (ES module, zero dependencies) |
| `assets.generated.mjs` | `HTML_EN`, `HTML_HE`, `MAINTENANCE_JS`, `API_JSON` — **generated** by `deploy/maintenance/build.mjs`, never edited by hand |
| `worker.test.mjs` | `node:test` suite with a mocked origin |
