#!/usr/bin/env bash
# Continuity ("maintenance") page contract — asserts what deploy/nginx-gateway.conf and
# deploy/nginx-weissman.conf actually DO when the backend cannot answer.
#
# The page is AUTOMATIC: nginx turns its own 502/504 (connection refused, connect timeout) into
# the branded HTTP 503 page, and stops the moment the backend answers again. Nothing is switched
# on by hand. That is exactly the kind of behaviour that only exists in the interaction between
# `proxy_intercept_errors`, `error_page` inheritance, internal locations and `map`s — none of which
# `nginx -t` can vouch for, and all of which have a failure mode that looks fine until the
# backend is actually down. The ones this suite pins:
#
#   * `proxy_intercept_errors on` must NOT swallow the backend's own 503s and 404s: the website's
#     demo-request form relies on a 503 from POST /api/public/demo-request while SMTP is
#     unconfigured, and an API 404 must stay a JSON 404, not become the marketing 404 page;
#   * /maintenance/maintenance.js must be a genuine 200 even while the announced-window flag
#     answers everything else with 503 — a browser refuses to run a script that arrives as 5xx;
#   * API / hook / WebSocket clients and `Accept: application/json` get api.json, /he gets Hebrew;
#   * every 503 carries Retry-After, Cache-Control: no-store, X-Weissman-Maintenance and the
#     security headers exactly once (the page location REPLACES the originating location's set);
#   * POST / DELETE / HEAD get the page too — a named-location error_page target keeps the
#     original method and nginx's static handler answers 405 to anything but GET/HEAD (measured;
#     the Kubernetes default backend had exactly that bug, so it is under the same test);
#   * the body follows the NORMALISED path: `/he/../api/health` is proxied as /api/health and
#     must get api.json, not the Hebrew page (measured on a map keyed on $request_uri);
#   * the page's internal URI is not reachable directly, and that 404 carries none of the
#     page's headers (a monitor keyed on X-Weissman-Maintenance must not read it as an outage);
#   * the marketing site and its 404 map keep working while the backend is down;
#   * the flag is re-read per request — on/off without a reload.
#
# Docker-free by design (the gateway-contract job needs a daemon; this one must also run on a
# laptop and in the systemd job): the REAL config files are copied, host paths and ports are
# rewritten into a temporary prefix, and four nginx masters run on 127.0.0.1:18080–18099 —
# the gateway, the VPS site (with a throw-away self-signed cert for its 443 block), the
# Kubernetes default backend (deploy/maintenance/src/k8s-default.conf, byte-identical to the
# ConfigMap key — `build.mjs --check` guards that) and a stub upstream that is started only
# for the "backend up" phase. Skips (exit 0) when nginx is not installed; every other problem
# is a failure.
#
# Usage: bash scripts/test_maintenance_contract.sh        (KEEP=1 keeps the work dir)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GW_PORT=18080
STUB_PORT=18082
VPS_HTTP_PORT=18083
VPS_HTTPS_PORT=18084
K8S_PORT=18085

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

for tool in nginx curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool unavailable"; exit 0; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/weissman-maint-XXXXXX")"
GWD="$WORK/gateway"; VD="$WORK/vps"; SD="$WORK/stub"; KD="$WORK/k8s"
HDR_FILE="$WORK/hdr"; BODY_FILE="$WORK/body"
DIST="$ROOT/deploy/maintenance/dist"

cleanup() {
  for d in "$GWD" "$VD" "$SD" "$KD"; do
    [[ -f "$d/nginx.pid" ]] && kill "$(cat "$d/nginx.pid")" >/dev/null 2>&1
  done
  sleep 0.2
  if [[ "${KEEP:-0}" == "1" ]]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# nginx registers a temp path for every proxy-style module compiled in, and creates it at
# startup even when unused. Point each one at the prefix — but only for modules that exist,
# because naming a directive of an absent module is a fatal config error.
NGINX_V="$(nginx -V 2>&1)"
temp_paths() {
  local d=$1 line="client_body_temp_path $d/tmp/client;"
  for m in proxy fastcgi uwsgi scgi; do
    grep -q -- "--without-http_${m}_module" <<<"$NGINX_V" || line+=" ${m}_temp_path $d/tmp/$m;"
  done
  printf '%s' "$line"
}
# As root the workers would drop to `nobody`, which cannot read a 0700 work dir; as an ordinary
# user (CI) nginx has no one to drop to and the directive would only draw a warning.
USER_LINE=""; [[ "$(id -u)" == "0" ]] && USER_LINE="user root;"
ERR_OPT=(); nginx -h 2>&1 | grep -q -- '-e filename' && ERR_OPT=(-e "__ERRLOG__")

# write_wrapper <dir> <extra http-level lines>
write_wrapper() {
  local d=$1 extra=${2:-}
  mkdir -p "$d/tmp"
  cat >"$d/nginx.conf" <<EOF
$USER_LINE
pid $d/nginx.pid;
error_log $d/error.log warn;
worker_processes 1;
events { worker_connections 128; }
http {
    types { text/html html; application/javascript js; application/json json; text/css css; image/svg+xml svg; }
    default_type application/octet-stream;
    access_log $d/access.log;
    $(temp_paths "$d")
    $extra
    include $d/site.conf;
}
EOF
}

# start_nginx <dir> <port> <label>
start_nginx() {
  local d=$1 port=$2 label=$3
  local errlog=("${ERR_OPT[@]/__ERRLOG__/$d/error.log}")
  if ! nginx -t -c "$d/nginx.conf" -p "$d" "${errlog[@]}" >"$d/nginx-t.out" 2>&1; then
    bad "$label: nginx -t rejected the config:"
    sed 's/^/        /' "$d/nginx-t.out"
    return 1
  fi
  ok "$label: nginx -t passes"
  nginx -c "$d/nginx.conf" -p "$d" "${errlog[@]}"
  for _ in $(seq 1 50); do
    curl -s -k -o /dev/null -m 1 "http://127.0.0.1:$port/" 2>/dev/null && return 0
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
    sleep 0.1
  done
  bad "$label: nothing listens on 127.0.0.1:$port after start"
  sed 's/^/        /' "$d/error.log" 2>/dev/null | tail -5
  return 1
}
stop_nginx() { [[ -f "$1/nginx.pid" ]] && kill "$(cat "$1/nginx.pid")" >/dev/null 2>&1; sleep 0.3; }

# ── Stub upstream: 200 JSON for everything, plus the two upstream answers that must survive ──
mkdir -p "$SD"
cat >"$SD/site.conf" <<EOF
server {
    listen 127.0.0.1:$STUB_PORT;
    default_type application/json;
    # The website's demo form: a LEGITIMATE upstream 503 that the gateway must pass through.
    location = /api/public/demo-request { return 503 '{"ok":false,"error":"smtp_unconfigured","stub":"demo-request"}'; }
    # An API 404 must stay the API's 404, not become the marketing 404 page.
    location = /api/nope { return 404 '{"ok":false,"error":"not_found","stub":"nope"}'; }
    location / { return 200 '{"ok":true,"stub":"upstream"}'; }
}
EOF
write_wrapper "$SD"
STUB_OK='{"ok":true,"stub":"upstream"}'
STUB_DEMO='{"ok":false,"error":"smtp_unconfigured","stub":"demo-request"}'
STUB_NOPE='{"ok":false,"error":"not_found","stub":"nope"}'

# ── Gateway: the real deploy/nginx-gateway.conf, host paths rewritten into the prefix ────────
mkdir -p "$GWD/conf.d" "$GWD/html/public/he" "$GWD/html/command-center" "$GWD/html/maintenance" "$GWD/state"
cp "$ROOT/deploy/nginx-security-headers.inc"       "$GWD/conf.d/security-headers.inc"
cp "$ROOT/deploy/nginx-strip-internal-headers.inc" "$GWD/conf.d/strip-internal-headers.inc"
cp -R "$DIST/." "$GWD/html/maintenance/"
printf 'MARKETING\n'     >"$GWD/html/public/index.html"
printf 'MARKETING-HE\n'  >"$GWD/html/public/he/index.html"
printf 'NOT-FOUND-EN\n'  >"$GWD/html/public/404.html"
printf 'NOT-FOUND-HE\n'  >"$GWD/html/public/he/404.html"
printf 'SPA-SHELL\n'     >"$GWD/html/command-center/index.html"
sed -e "s|server backend:8000;|server 127.0.0.1:$STUB_PORT;|" \
    -e "s|listen 8080;|listen 127.0.0.1:$GW_PORT;|" \
    -e "s|/usr/share/nginx/html|$GWD/html|g" \
    -e "s|/var/lib/weissman/maintenance|$GWD/state|g" \
    -e "s|/etc/nginx/conf.d/|$GWD/conf.d/|g" \
    "$ROOT/deploy/nginx-gateway.conf" >"$GWD/site.conf"
# Each rewrite must have hit, or a refactor of the real config would silently untether the test.
for needle in "127.0.0.1:$STUB_PORT" "listen 127.0.0.1:$GW_PORT" "$GWD/html/maintenance" "$GWD/state/maintenance.on" "$GWD/conf.d/security-headers.inc"; do
  grep -qF -- "$needle" "$GWD/site.conf" || bad "gateway: expected '$needle' in the rewritten config (sed anchor drifted?)"
done
for stale in "backend:8000" "/usr/share/nginx" "/var/lib/weissman" "/etc/nginx/conf.d"; do
  grep -v '^[[:space:]]*#' "$GWD/site.conf" | grep -qF -- "$stale" && bad "gateway: '$stale' survived the rewrite"
done
write_wrapper "$GWD"
GW_FLAG="$GWD/state/maintenance.on"
GW_STATUS="$GWD/state/status.json"

# ── VPS site: the real deploy/nginx-weissman.conf, self-signed TLS, prefix paths ─────────────
mkdir -p "$VD/tls" "$VD/opt/maintenance/state"
cp -R "$DIST/." "$VD/opt/maintenance/"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=weissmancyber.com" \
  -keyout "$VD/tls/key.pem" -out "$VD/tls/cert.pem" >/dev/null 2>&1 \
  || bad "vps: openssl could not mint a self-signed certificate"
printf '# stand-in for certbot options-ssl-nginx.conf (the site sets its own TLS policy)\n' >"$VD/tls/options-ssl-nginx.conf"
sed -e "s|server 127.0.0.1:8000;|server 127.0.0.1:$STUB_PORT;|" \
    -e "s|listen 80;|listen 127.0.0.1:$VPS_HTTP_PORT;|" \
    -e "s|listen 443 ssl http2;|listen 127.0.0.1:$VPS_HTTPS_PORT ssl http2;|" \
    -e '/listen \[::\]/d' \
    -e "s|/etc/letsencrypt/live/weissmancyber.com/fullchain.pem|$VD/tls/cert.pem|" \
    -e "s|/etc/letsencrypt/live/weissmancyber.com/privkey.pem|$VD/tls/key.pem|" \
    -e "s|/etc/letsencrypt/options-ssl-nginx.conf|$VD/tls/options-ssl-nginx.conf|" \
    -e "s|/opt/weissman|$VD/opt|g" \
    "$ROOT/deploy/nginx-weissman.conf" >"$VD/site.conf"
for needle in "127.0.0.1:$STUB_PORT" "listen 127.0.0.1:$VPS_HTTP_PORT" "listen 127.0.0.1:$VPS_HTTPS_PORT ssl" "$VD/tls/cert.pem" "$VD/opt/maintenance/state/maintenance.on"; do
  grep -qF -- "$needle" "$VD/site.conf" || bad "vps: expected '$needle' in the rewritten config (sed anchor drifted?)"
done
# Directives only — the real file keeps a commented-out certbot ssl_dhparam line as a hint.
for stale in "127.0.0.1:8000" "/etc/letsencrypt" "/opt/weissman" "listen [::]"; do
  grep -v '^[[:space:]]*#' "$VD/site.conf" | grep -qF -- "$stale" && bad "vps: '$stale' survived the rewrite"
done
# The site needs $connection_upgrade from the http-level snippet, exactly as on a real host.
write_wrapper "$VD" "include $ROOT/deploy/nginx-snippet-websocket-map.conf;"
VPS_FLAG="$VD/opt/maintenance/state/maintenance.on"
VPS_STATUS="$VD/opt/maintenance/state/status.json"

# ── Kubernetes default backend: the ConfigMap's nginx, files laid out as the pod mounts them ──
mkdir -p "$KD/html"
cp "$DIST/index.html"    "$KD/html/index.html"
cp "$DIST/he/index.html" "$KD/html/he.html"
cp "$DIST/maintenance.js" "$KD/html/maintenance.js"
cp "$DIST/api.json"      "$KD/html/api.json"
sed -e "s|listen 8080 default_server;|listen 127.0.0.1:$K8S_PORT default_server;|" \
    -e "s|/usr/share/nginx/html|$KD/html|g" \
    "$ROOT/deploy/maintenance/src/k8s-default.conf" >"$KD/site.conf"
for needle in "listen 127.0.0.1:$K8S_PORT" "root $KD/html;"; do
  grep -qF -- "$needle" "$KD/site.conf" || bad "k8s: expected '$needle' in the rewritten config (sed anchor drifted?)"
done
grep -v '^[[:space:]]*#' "$KD/site.conf" | grep -qF -- "/usr/share/nginx" && bad "k8s: '/usr/share/nginx' survived the rewrite"
write_wrapper "$KD"

[[ "$fail" -eq 0 ]] || { printf '\nMaintenance contract: %d passed, %d failed (setup)\n' "$pass" "$fail"; exit 1; }

start_nginx "$GWD" "$GW_PORT" "gateway" || exit 1
start_nginx "$VD"  "$VPS_HTTP_PORT" "vps" || exit 1
start_nginx "$KD"  "$K8S_PORT" "k8s default backend" || exit 1

GW="http://127.0.0.1:$GW_PORT"
VPS="https://127.0.0.1:$VPS_HTTPS_PORT"
VPS_PLAIN="http://127.0.0.1:$VPS_HTTP_PORT"
K8S="http://127.0.0.1:$K8S_PORT"

# ── request helpers ─────────────────────────────────────────────────────────────
# req <url> [curl args…]  → CODE, SECS; headers in $HDR_FILE, body in $BODY_FILE
req() {
  local url=$1; shift
  local out
  out="$(curl -s -k -o "$BODY_FILE" -D "$HDR_FILE" -m 15 -w '%{http_code} %{time_total}' "$@" "$url")"
  CODE="${out%% *}"; SECS="${out#* }"
}
hdr()       { awk -v k="$1:" 'tolower($1)==tolower(k){sub(/^[^:]*:[ \t]*/,""); sub(/\r$/,""); print; exit}' "$HDR_FILE"; }
hdr_count() { grep -ci "^$1:" "$HDR_FILE"; }
body_is()   { [[ "$(cat "$BODY_FILE")" == "$1" ]]; }
body_has()  { grep -qF -- "$1" "$BODY_FILE"; }

# The full 503 header contract, asserted on every branded response.
assert_maint_headers() {
  local label=$1 want_csp=${2:-1}
  [[ "$(hdr retry-after)" == "30" ]]              && ok "$label: Retry-After: 30"                 || bad "$label: Retry-After is '$(hdr retry-after)'"
  grep -qi 'no-store' <<<"$(hdr cache-control)"    && ok "$label: Cache-Control no-store"          || bad "$label: Cache-Control is '$(hdr cache-control)'"
  [[ "$(hdr x-weissman-maintenance)" == "1" ]]     && ok "$label: X-Weissman-Maintenance: 1"       || bad "$label: X-Weissman-Maintenance is '$(hdr x-weissman-maintenance)'"
  [[ "$(hdr_count content-security-policy)" == "$want_csp" ]] && ok "$label: CSP present exactly once" || bad "$label: CSP appears $(hdr_count content-security-policy) times"
  [[ "$(hdr x-content-type-options)" == "nosniff" ]] && ok "$label: nosniff"                       || bad "$label: X-Content-Type-Options is '$(hdr x-content-type-options)'"
  grep -qi 'noindex' <<<"$(hdr x-robots-tag)"      && ok "$label: X-Robots-Tag noindex"            || bad "$label: X-Robots-Tag is '$(hdr x-robots-tag)'"
}
assert_html_en() {
  local label=$1
  [[ "$CODE" == "503" ]] && ok "$label: 503" || bad "$label: expected 503, got $CODE"
  grep -qi '^text/html' <<<"$(hdr content-type)" && ok "$label: text/html" || bad "$label: Content-Type is '$(hdr content-type)'"
  body_has '<html lang="en"' && ok "$label: English page (lang=en)" || bad "$label: body is not the English page"
  body_has 'WEISSMAN' && body_has 'id="maint-state"' && ok "$label: wordmark + #maint-state present" || bad "$label: wordmark / #maint-state missing"
}
assert_html_he() {
  local label=$1
  [[ "$CODE" == "503" ]] && ok "$label: 503" || bad "$label: expected 503, got $CODE"
  body_has '<html lang="he"' && body_has 'dir="rtl"' && ok "$label: Hebrew page (lang=he, rtl)" || bad "$label: body is not the Hebrew page"
}
assert_json() {
  local label=$1
  [[ "$CODE" == "503" ]] && ok "$label: 503" || bad "$label: expected 503, got $CODE"
  grep -qi '^application/json' <<<"$(hdr content-type)" && ok "$label: application/json" || bad "$label: Content-Type is '$(hdr content-type)'"
  cmp -s "$BODY_FILE" "$DIST/api.json" && ok "$label: body is dist/api.json byte-for-byte" || bad "$label: body differs from dist/api.json"
}
# A response that is NOT the page must not look like one to a monitor.
assert_not_branded() {
  local label=$1
  [[ -z "$(hdr retry-after)" && -z "$(hdr x-weissman-maintenance)" ]] && ok "$label: no Retry-After / X-Weissman-Maintenance" || bad "$label: carries Retry-After '$(hdr retry-after)' / X-Weissman-Maintenance '$(hdr x-weissman-maintenance)'"
}

# ═══ Gateway — backend down, NO flag anywhere: the primary, automatic path ═══════════════════
echo "── gateway: backend down, no flag"
req "$GW/"
[[ "$CODE" == "200" ]] && body_is "MARKETING" && ok "GET / is the static marketing page (200)" || bad "GET / returned $CODE '$(head -c 40 "$BODY_FILE")'"
[[ -z "$(hdr x-weissman-maintenance)" ]] && ok "static page carries no X-Weissman-Maintenance" || bad "static page carries X-Weissman-Maintenance"
req "$GW/he/"
[[ "$CODE" == "200" ]] && body_is "MARKETING-HE" && ok "GET /he/ is the static Hebrew marketing page" || bad "GET /he/ returned $CODE"

req "$GW/api/health"
assert_json "/api/health"
assert_maint_headers "/api/health"
awk -v t="$SECS" 'BEGIN{exit !(t+0 < 3)}' && ok "/api/health answered in ${SECS}s (dead upstream fails fast)" || bad "/api/health took ${SECS}s"
req "$GW/api/health?probe=1"
assert_json "/api/health?probe=1"
req "$GW/api/login" -X POST -H 'Content-Type: application/json' --data '{}'
assert_json "POST /api/login"
req "$GW/api/v1/things/42" -X DELETE
assert_json "DELETE /api/v1/things/42"
req "$GW/api/health" -I
[[ "$CODE" == "503" ]] && [[ "$(hdr x-weissman-maintenance)" == "1" ]] && ok "HEAD /api/health: 503 + X-Weissman-Maintenance" || bad "HEAD /api/health returned $CODE"
req "$GW/maintenance/_503"
[[ "$CODE" == "404" ]] && ok "the page's internal URI is not reachable directly (404)" || bad "/maintenance/_503 returned $CODE when asked for directly"
assert_not_branded "direct /maintenance/_503"
# The body follows the path nginx actually routed (normalised $uri), not the raw request line.
req "$GW/he/../api/health" --path-as-is
assert_json "/he/../api/health sent as-is (proxied as /api/health)"
req "$GW/api%2Fhealth"
assert_json "/api%2Fhealth (decoded to /api/health)"
req "$GW/he/../status" --path-as-is
assert_html_en "/he/../status sent as-is (proxied as /status: English, not Hebrew)"
req "$GW/ws/events"
assert_json "/ws/events"
req "$GW/hooks/paddle"
assert_json "/hooks/paddle"
req "$GW/install/agent.sh"
assert_json "/install/agent.sh"

req "$GW/status"
assert_html_en "/status"
assert_maint_headers "/status"
req "$GW/status" -H 'Accept: application/json'
assert_json "/status with Accept: application/json"

req "$GW/maintenance/maintenance.js"
[[ "$CODE" == "200" ]] && ok "/maintenance/maintenance.js is 200" || bad "/maintenance/maintenance.js returned $CODE"
grep -qi '^application/javascript' <<<"$(hdr content-type)" && ok "maintenance.js is application/javascript" || bad "maintenance.js Content-Type is '$(hdr content-type)'"
grep -qi 'no-store' <<<"$(hdr cache-control)" && ok "maintenance.js is no-store" || bad "maintenance.js Cache-Control is '$(hdr cache-control)'"
cmp -s "$BODY_FILE" "$DIST/maintenance.js" && ok "maintenance.js body matches dist" || bad "maintenance.js body differs from dist"
[[ "$(hdr_count content-security-policy)" == "1" ]] && ok "maintenance.js carries the security headers" || bad "maintenance.js CSP count is $(hdr_count content-security-policy)"
req "$GW/maintenance/he/index.html"
[[ "$CODE" == "200" ]] && body_has '<html lang="he"' && ok "/maintenance/he/index.html previews as 200" || bad "/maintenance/he/index.html returned $CODE"

req "$GW/maintenance/status.json"
[[ "$CODE" == "404" ]] && ok "/maintenance/status.json is 404 with no announced window" || bad "/maintenance/status.json returned $CODE without a file"
cp "$DIST/status.example.json" "$GW_STATUS"
req "$GW/maintenance/status.json"
[[ "$CODE" == "200" ]] && ok "/maintenance/status.json is 200 once the state dir has one" || bad "/maintenance/status.json returned $CODE with a file"
grep -qi '^application/json' <<<"$(hdr content-type)" && ok "status.json is application/json" || bad "status.json Content-Type is '$(hdr content-type)'"
grep -qi 'no-store' <<<"$(hdr cache-control)" && ok "status.json is no-store" || bad "status.json Cache-Control is '$(hdr cache-control)'"
cmp -s "$BODY_FILE" "$GW_STATUS" && ok "status.json body is the state file" || bad "status.json body differs"
rm -f "$GW_STATUS"

req "$GW/definitely-not-a-real-path-9f3a"
[[ "$CODE" == "404" ]] && body_is "NOT-FOUND-EN" && ok "unknown path is still the English 404 (map intact)" || bad "unknown path returned $CODE '$(head -c 40 "$BODY_FILE")'"
req "$GW/he/definitely-not-a-real-path-9f3a"
[[ "$CODE" == "404" ]] && body_is "NOT-FOUND-HE" && ok "unknown Hebrew path is still the Hebrew 404" || bad "unknown Hebrew path returned $CODE '$(head -c 40 "$BODY_FILE")'"
req "$GW/command-center/"
[[ "$CODE" == "200" ]] && body_is "SPA-SHELL" && ok "Command Center shell still serves (200) with the backend down" || bad "/command-center/ returned $CODE"

# ═══ Gateway — announced-window flag present ════════════════════════════════════════════════
echo "── gateway: flag present"
touch "$GW_FLAG"
req "$GW/"
assert_html_en "flag: /"
assert_maint_headers "flag: /"
req "$GW/he/"
assert_html_he "flag: /he/"
assert_maint_headers "flag: /he/"
req "$GW/he"
assert_html_he "flag: /he (no slash)"
req "$GW/he?x=1"
assert_html_he "flag: /he?x=1"
req "$GW/api/anything"
assert_json "flag: /api/anything"
assert_maint_headers "flag: /api/anything"
req "$GW/he/../api/anything" --path-as-is
assert_json "flag: /he/../api/anything sent as-is"
req "$GW/command-center/"
assert_html_en "flag: /command-center/"
req "$GW/maintenance/maintenance.js"
[[ "$CODE" == "200" ]] && cmp -s "$BODY_FILE" "$DIST/maintenance.js" && ok "flag: /maintenance/maintenance.js still 200 (assets bypass the flag)" || bad "flag: maintenance.js returned $CODE"
# A missing status.json must stay a 404 while flagged: the static 404 must not detour through
# the marketing 404 page and re-trip the flag (the page reads 404 as "nothing announced").
req "$GW/maintenance/status.json"
[[ "$CODE" == "404" ]] && ok "flag: /maintenance/status.json is 404 when no window is announced" || bad "flag: /maintenance/status.json without a file returned $CODE (expected 404)"
req "$GW/maintenance/does-not-exist.js"
[[ "$CODE" == "404" ]] && ok "flag: a missing /maintenance/ asset is 404" || bad "flag: missing /maintenance/ asset returned $CODE"
req "$GW/maintenance/_503"
[[ "$CODE" == "404" ]] && ok "flag: the page's internal URI asked for directly is still 404" || bad "flag: /maintenance/_503 returned $CODE"
cp "$DIST/status.example.json" "$GW_STATUS"
req "$GW/maintenance/status.json"
[[ "$CODE" == "200" ]] && cmp -s "$BODY_FILE" "$GW_STATUS" && ok "flag: /maintenance/status.json still 200" || bad "flag: status.json returned $CODE"
rm -f "$GW_STATUS"
rm -f "$GW_FLAG"
req "$GW/"
[[ "$CODE" == "200" ]] && body_is "MARKETING" && ok "flag removed: / is 200 again with no reload" || bad "flag removed: / returned $CODE"

# ═══ VPS — backend down, no flag ════════════════════════════════════════════════════════════
echo "── vps: backend down, no flag"
req "$VPS_PLAIN/anything?x=1" -H 'Host: weissmancyber.com'
[[ "$CODE" == "301" ]] && ok "port 80 redirects (301)" || bad "port 80 returned $CODE"
[[ "$(hdr location)" == "https://weissmancyber.com/anything?x=1" ]] && ok "port 80 Location is https://weissmancyber.com/anything?x=1" || bad "port 80 Location is '$(hdr location)'"

req "$VPS/"
assert_html_en "vps /"
assert_maint_headers "vps /"
[[ -n "$(hdr strict-transport-security)" ]] && ok "vps /: HSTS present" || bad "vps /: HSTS missing"
[[ "$(hdr x-frame-options)" == "DENY" ]] && ok "vps /: X-Frame-Options DENY" || bad "vps /: X-Frame-Options is '$(hdr x-frame-options)'"
req "$VPS/dashboard?tab=1"
assert_html_en "vps /dashboard?tab=1"
req "$VPS/command-center/"
assert_html_en "vps /command-center/"
req "$VPS/he/"
assert_html_he "vps /he/"
assert_maint_headers "vps /he/"
req "$VPS/he"
assert_html_he "vps /he"
req "$VPS/he/pricing"
assert_html_he "vps /he/pricing"
req "$VPS/hello"
assert_html_en "vps /hello (not Hebrew)"
req "$VPS/api/health"
assert_json "vps /api/health"
assert_maint_headers "vps /api/health"
awk -v t="$SECS" 'BEGIN{exit !(t+0 < 3)}' && ok "vps /api/health answered in ${SECS}s" || bad "vps /api/health took ${SECS}s"
req "$VPS/hooks/ci" -X POST -H 'Content-Type: application/json' --data '{"event":"deploy"}'
assert_json "vps POST /hooks/ci"
req "$VPS/dashboard" -X POST --data 'a=1'
assert_html_en "vps POST /dashboard"
req "$VPS/maintenance/_503"
[[ "$CODE" == "404" ]] && ok "vps: the page's internal URI is not reachable directly (404)" || bad "vps /maintenance/_503 returned $CODE"
assert_not_branded "vps direct /maintenance/_503"
req "$VPS/he/../api/health" --path-as-is
assert_json "vps /he/../api/health sent as-is (proxied as /api/health)"
req "$VPS/he/../dashboard" --path-as-is
assert_html_en "vps /he/../dashboard sent as-is (English, not Hebrew)"
req "$VPS/ws/live"
assert_json "vps /ws/live"
req "$VPS/install/agent.sh"
assert_json "vps /install/agent.sh"
req "$VPS/" -H 'Accept: application/json'
assert_json "vps / with Accept: application/json"

req "$VPS/maintenance/maintenance.js"
[[ "$CODE" == "200" ]] && cmp -s "$BODY_FILE" "$DIST/maintenance.js" && ok "vps /maintenance/maintenance.js is 200 and matches dist" || bad "vps maintenance.js returned $CODE"
grep -qi '^application/javascript' <<<"$(hdr content-type)" && ok "vps maintenance.js is application/javascript" || bad "vps maintenance.js Content-Type is '$(hdr content-type)'"
grep -qi 'no-store' <<<"$(hdr cache-control)" && ok "vps maintenance.js is no-store" || bad "vps maintenance.js Cache-Control is '$(hdr cache-control)'"
req "$VPS/maintenance/status.json"
[[ "$CODE" == "404" ]] && ok "vps /maintenance/status.json is 404 with no announced window" || bad "vps status.json returned $CODE without a file"
cp "$DIST/status.example.json" "$VPS_STATUS"
req "$VPS/maintenance/status.json"
[[ "$CODE" == "200" ]] && cmp -s "$BODY_FILE" "$VPS_STATUS" && grep -qi 'no-store' <<<"$(hdr cache-control)" && ok "vps /maintenance/status.json is 200 no-store once present" || bad "vps status.json returned $CODE"
req "$VPS/maintenance/state/status.json"
[[ "$CODE" == "404" ]] && ok "vps: the state dir is not browsable under /maintenance/state/" || bad "vps /maintenance/state/status.json returned $CODE"
rm -f "$VPS_STATUS"

# ═══ VPS — flag present ═════════════════════════════════════════════════════════════════════
echo "── vps: flag present"
touch "$VPS_FLAG"
req "$VPS/"
assert_html_en "vps flag: /"
assert_maint_headers "vps flag: /"
req "$VPS/he/"
assert_html_he "vps flag: /he/"
req "$VPS/api/anything"
assert_json "vps flag: /api/anything"
req "$VPS/maintenance/maintenance.js"
[[ "$CODE" == "200" ]] && ok "vps flag: /maintenance/maintenance.js still 200" || bad "vps flag: maintenance.js returned $CODE"
req "$VPS/maintenance/status.json"
[[ "$CODE" == "404" ]] && ok "vps flag: /maintenance/status.json is 404 when no window is announced" || bad "vps flag: status.json without a file returned $CODE"
req "$VPS/maintenance/state/maintenance.on"
[[ "$CODE" == "404" ]] && ok "vps flag: the flag file itself is not served" || bad "vps flag: /maintenance/state/maintenance.on returned $CODE"
rm -f "$VPS_FLAG"

# ═══ Kubernetes default backend: routed on ingress-nginx's headers, or on its own URI ═══════
# ingress-nginx re-issues an intercepted 502/503/504 to this backend as "/" with the ORIGINAL
# method and X-Original-URI / X-Format; a Service with no ready endpoints forwards verbatim.
echo "── k8s default backend"
req "$K8S/"
assert_html_en "k8s GET /"
assert_maint_headers "k8s GET /"
[[ "$(hdr x-frame-options)" == "DENY" ]] && ok "k8s GET /: X-Frame-Options DENY" || bad "k8s GET /: X-Frame-Options is '$(hdr x-frame-options)'"
req "$K8S/" -X POST -H 'Content-Type: application/json' --data '{}' -H 'X-Original-URI: /api/login' -H 'X-Code: 502'
assert_json "k8s POST / for /api/login (not 405)"
assert_maint_headers "k8s POST / for /api/login"
req "$K8S/" -X DELETE -H 'X-Original-URI: /he/x'
assert_html_he "k8s DELETE / for /he/x (not 405)"
req "$K8S/" -X OPTIONS
assert_html_en "k8s OPTIONS / (not 405)"
req "$K8S/api/v1/things/42" -X PUT --data '{}'
assert_json "k8s PUT /api/v1/things/42 forwarded verbatim (not 405)"
req "$K8S/" -H 'X-Original-URI: /hooks/paddle'
assert_json "k8s / for /hooks/paddle"
req "$K8S/" -H 'X-Original-URI: /ws/events'
assert_json "k8s / for /ws/events"
req "$K8S/" -H 'X-Original-URI: /install/agent.sh'
assert_json "k8s / for /install/agent.sh"
req "$K8S/" -H 'X-Original-URI: /apiary'
assert_html_en "k8s / for /apiary (prefix only matches /api/)"
req "$K8S/" -H 'X-Original-URI: /he/'
assert_html_he "k8s / for /he/"
req "$K8S/he"
assert_html_he "k8s /he forwarded verbatim"
req "$K8S/" -H 'X-Format: application/json'
assert_json "k8s / with X-Format: application/json"
req "$K8S/" -H 'X-Format: application/json' -H 'X-Original-URI: /he/'
assert_json "k8s / JSON wins over the Hebrew path"
req "$K8S/" -I -H 'X-Original-URI: /api/x'
[[ "$CODE" == "503" ]] && [[ "$(hdr x-weissman-maintenance)" == "1" ]] && ok "k8s HEAD /: 503 + X-Weissman-Maintenance" || bad "k8s HEAD / returned $CODE"
req "$K8S/maintenance/maintenance.js"
[[ "$CODE" == "200" ]] && cmp -s "$BODY_FILE" "$DIST/maintenance.js" && ok "k8s /maintenance/maintenance.js is 200 and matches dist" || bad "k8s maintenance.js returned $CODE"
grep -qi '^application/javascript' <<<"$(hdr content-type)" && ok "k8s maintenance.js is application/javascript" || bad "k8s maintenance.js Content-Type is '$(hdr content-type)'"
req "$K8S/" -H 'X-Original-URI: /maintenance/maintenance.js'
[[ "$CODE" == "200" ]] && cmp -s "$BODY_FILE" "$DIST/maintenance.js" && ok "k8s / for /maintenance/maintenance.js is the script, 200" || bad "k8s script via X-Original-URI returned $CODE"
req "$K8S/maintenance/status.json"
[[ "$CODE" == "404" ]] && ok "k8s /maintenance/status.json is 404 (no window on this layer)" || bad "k8s status.json returned $CODE"
assert_not_branded "k8s /maintenance/status.json"
req "$K8S/healthz"
[[ "$CODE" == "200" ]] && body_is "ok" && ok "k8s /healthz is 200 ok (probes)" || bad "k8s /healthz returned $CODE '$(head -c 20 "$BODY_FILE")'"
req "$K8S/_503"
[[ "$CODE" == "404" ]] && ok "k8s: the page's internal URI is not reachable directly (404)" || bad "k8s /_503 returned $CODE"
assert_not_branded "k8s direct /_503"
grep -qE '^[[:space:]]*if[[:space:]]*\(' "$ROOT/deploy/maintenance/src/k8s-default.conf" && bad "k8s: default.conf uses \`if\`" || ok "k8s: default.conf has no \`if\`"

# ═══ Backend UP: start the stub, both edges must get out of the way ═════════════════════════
echo "── backend up (stub upstream)"
start_nginx "$SD" "$STUB_PORT" "stub upstream" || exit 1

req "$GW/api/health"
[[ "$CODE" == "200" ]] && body_is "$STUB_OK" && ok "gateway /api/health passes through (200, upstream body)" || bad "gateway /api/health returned $CODE '$(head -c 60 "$BODY_FILE")'"
[[ -z "$(hdr x-weissman-maintenance)" ]] && ok "gateway 200 carries no X-Weissman-Maintenance" || bad "gateway 200 carries X-Weissman-Maintenance"
req "$GW/api/public/demo-request" -X POST -H 'Content-Type: application/json' --data '{"email":"x@example.com"}'
[[ "$CODE" == "503" ]] && ok "gateway: upstream 503 keeps its status" || bad "gateway: upstream 503 became $CODE"
body_is "$STUB_DEMO" && ok "gateway: upstream 503 body passes through UNCHANGED (proxy_intercept_errors leaves it alone)" || bad "gateway: upstream 503 body was replaced: '$(head -c 80 "$BODY_FILE")'"
[[ -z "$(hdr x-weissman-maintenance)" ]] && [[ -z "$(hdr retry-after)" ]] && ok "gateway: upstream 503 carries no maintenance headers" || bad "gateway: upstream 503 gained maintenance headers"
req "$GW/api/nope"
[[ "$CODE" == "404" ]] && body_is "$STUB_NOPE" && ok "gateway: upstream 404 stays the API's own 404 (not the marketing page)" || bad "gateway: upstream 404 became $CODE '$(head -c 60 "$BODY_FILE")'"
req "$GW/status"
[[ "$CODE" == "200" ]] && body_is "$STUB_OK" && ok "gateway /status passes through (200)" || bad "gateway /status returned $CODE"
req "$GW/"
[[ "$CODE" == "200" ]] && body_is "MARKETING" && ok "gateway / is 200 with the backend up and no flag" || bad "gateway / returned $CODE"
touch "$GW_FLAG"
req "$GW/api/health"
assert_json "gateway flag with backend up: /api/health"
rm -f "$GW_FLAG"
req "$GW/api/health"
[[ "$CODE" == "200" ]] && ok "gateway flag removed: /api/health is 200 again" || bad "gateway flag removed: /api/health returned $CODE"

req "$VPS/api/health"
[[ "$CODE" == "200" ]] && body_is "$STUB_OK" && ok "vps /api/health passes through (200, upstream body)" || bad "vps /api/health returned $CODE '$(head -c 60 "$BODY_FILE")'"
[[ -z "$(hdr x-weissman-maintenance)" ]] && ok "vps 200 carries no X-Weissman-Maintenance" || bad "vps 200 carries X-Weissman-Maintenance"
req "$VPS/api/public/demo-request" -X POST -H 'Content-Type: application/json' --data '{"email":"x@example.com"}'
[[ "$CODE" == "503" ]] && body_is "$STUB_DEMO" && ok "vps: upstream 503 passes through UNCHANGED" || bad "vps: upstream 503 became $CODE '$(head -c 80 "$BODY_FILE")'"
[[ -z "$(hdr x-weissman-maintenance)" ]] && [[ -z "$(hdr retry-after)" ]] && ok "vps: upstream 503 carries no maintenance headers" || bad "vps: upstream 503 gained maintenance headers"
req "$VPS/api/nope"
[[ "$CODE" == "404" ]] && body_is "$STUB_NOPE" && ok "vps: upstream 404 passes through" || bad "vps: upstream 404 became $CODE"
req "$VPS/"
[[ "$CODE" == "200" ]] && body_is "$STUB_OK" && ok "vps / passes through (200) with the backend up" || bad "vps / returned $CODE"
touch "$VPS_FLAG"
req "$VPS/"
assert_html_en "vps flag with backend up: /"
rm -f "$VPS_FLAG"
req "$VPS/"
[[ "$CODE" == "200" ]] && ok "vps flag removed: / is 200 again" || bad "vps flag removed: / returned $CODE"

# ═══ Backend goes away again: the page must come back without any reload ═══════════════════
stop_nginx "$SD"
req "$GW/api/health"
assert_json "gateway after the backend went away again: /api/health"
req "$VPS/"
assert_html_en "vps after the backend went away again: /"

# nginx logs the expected "connect() failed (111)" as [error]; anything louder is a real
# problem (a [crit] stat() on the flag path, for one, silently disables the flag).
for d in "$GWD" "$VD" "$KD"; do
  if grep -qE '\[(crit|alert|emerg)\]' "$d/error.log" 2>/dev/null; then
    bad "$(basename "$d"): nginx error.log has crit/alert/emerg lines:"
    grep -E '\[(crit|alert|emerg)\]' "$d/error.log" | tail -3 | sed 's/^/        /'
  else
    ok "$(basename "$d"): no crit/alert/emerg in nginx error.log"
  fi
done

echo
printf 'Maintenance contract: %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
