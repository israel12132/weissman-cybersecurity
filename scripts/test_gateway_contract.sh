#!/usr/bin/env bash
# Gateway security contract — asserts what deploy/nginx-gateway.conf actually DOES.
#
# Nothing in CI exercised the gateway. The OWASP ZAP baseline targets the backend directly on
# :18000, and every UI E2E does the same, so the whole edge layer — security headers, the
# X-Forwarded-For trust boundary, the SPA redirect, the unknown-path response — shipped untested.
# That is the layer where several real defects lived:
#
#   * XFF was trusted from all of RFC1918, so any host on the deployment's LAN could forge its
#     source IP and bypass the per-IP login throttle entirely;
#   * `/command-center` without a trailing slash returned 200 and the marketing homepage, so the
#     natural URL told users the application did not exist;
#   * the obvious fix for that emitted `Location: http://host:8080/...`, a port that is not
#     published, because nginx makes redirects absolute using its own listen port.
#
# Runs the REAL config against a stub upstream, so it needs no database, no frontend build and no
# compose stack. Usage: bash scripts/test_gateway_contract.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET=weissman-gwtest-net
UPSTREAM=weissman-gwtest-upstream
GATEWAY=weissman-gwtest-gateway
WORK="$(mktemp -d)"

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

cleanup() {
  docker rm -f "$GATEWAY" "$UPSTREAM" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker unavailable"; exit 0; }

# The real config names its upstream `backend:8000`; the stub answers on that name.
docker network create "$NET" >/dev/null 2>&1 || true
cat >"$WORK/upstream.conf" <<'EOF'
server {
    listen 8000;
    location / { add_header Content-Type application/json; return 200 '{"ok":true}'; }
}
EOF
docker run -d --name "$UPSTREAM" --network "$NET" --network-alias backend \
  -v "$WORK/upstream.conf:/etc/nginx/conf.d/default.conf:ro" \
  nginxinc/nginx-unprivileged:1.29-alpine >/dev/null 2>&1

# Serve the real gateway config with a minimal document root.
mkdir -p "$WORK/conf" "$WORK/html/command-center" "$WORK/html/public/.well-known"
cp "$ROOT/deploy/nginx-gateway.conf" "$WORK/conf/default.conf"
cp "$ROOT/deploy/nginx-security-headers.inc" "$WORK/conf/security-headers.inc"
printf 'SPA-SHELL\n'  > "$WORK/html/command-center/index.html"
printf 'MARKETING\n'  > "$WORK/html/index.html"
mkdir -p "$WORK/html/command-center/assets"
printf 'console.log(1)\n' > "$WORK/html/command-center/assets/ok-test.js"

docker run -d --name "$GATEWAY" --network "$NET" -p 127.0.0.1:58089:8080 \
  -v "$WORK/conf:/etc/nginx/conf.d:ro" \
  -v "$WORK/html:/usr/share/nginx/html:ro" \
  nginxinc/nginx-unprivileged:1.29-alpine >/dev/null 2>&1

for _ in $(seq 1 40); do
  curl -s -o /dev/null -m 2 http://127.0.0.1:58089/ && break
  sleep 0.5
done
if ! docker ps --format '{{.Names}}' | grep -q "^${GATEWAY}$"; then
  echo "  FAIL  gateway container did not start:"
  docker logs "$GATEWAY" 2>&1 | tail -5 | sed 's/^/        /'
  exit 1
fi

B=http://127.0.0.1:58089

# ── X-Forwarded-For trust boundary ──────────────────────────────────────────────
# The request arrives from the Docker bridge, which is NOT in the trusted list (only loopback
# and the pinned compose-bridge gateway are), so a forged header must not become $remote_addr.
docker exec "$GATEWAY" sh -c 'true' >/dev/null 2>&1
curl -s -o /dev/null -m 5 -H 'X-Forwarded-For: 198.51.100.9' "$B/api/health?gwtest_xff=1"
sleep 1
if docker logs "$GATEWAY" 2>&1 | grep -q '^198\.51\.100\.9 .*gwtest_xff'; then
  bad "forged X-Forwarded-For was accepted as the client address"
else
  ok "forged X-Forwarded-For from an untrusted peer is not honoured"
fi

# ── SPA redirect ────────────────────────────────────────────────────────────────
code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$B/command-center")"
loc="$(curl -s -o /dev/null -m 5 -D- "$B/command-center" | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r')"
[[ "$code" == "301" ]] && ok "/command-center redirects (301)" || bad "/command-center returned $code, not 301"
# Relative, so it cannot point at nginx's internal listen port behind a proxy.
if [[ "$loc" == "/command-center/" ]]; then
  ok "redirect Location is relative (/command-center/)"
else
  bad "redirect Location is '$loc' — an absolute URL here leaks nginx's internal port"
fi
body="$(curl -sL -m 5 "$B/command-center" | head -1)"
[[ "$body" == "SPA-SHELL" ]] && ok "following the redirect reaches the SPA" || bad "redirect landed on '$body'"

# ── Unknown paths must 404, not serve the homepage with 200 ─────────────────────
code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$B/definitely-not-a-real-path-9f3a")"
[[ "$code" == "404" ]] && ok "unknown path returns 404" || bad "unknown path returned $code (a 200 makes every typo look like a real page)"

# ── Hashed SPA assets: hit immutable, miss must not be cached ───────────────────
# A rolling deploy can 404 a brand-new chunk for a few seconds. If that 404 is
# `Cache-Control: immutable`, the browser keeps it for a year and the Command Center
# surfaces "error loading dynamically imported module" even after the file exists.
hit="$(curl -s -o /dev/null -m 5 -D- "$B/command-center/assets/ok-test.js")"
code="$(printf '%s' "$hit" | awk 'NR==1{print $2}')"
cc="$(printf '%s' "$hit" | awk 'tolower($1)=="cache-control:"{print tolower($0)}')"
[[ "$code" == "200" ]] && ok "hashed asset hit returns 200" || bad "hashed asset hit returned $code"
if grep -q 'immutable' <<<"$cc"; then
  ok "hashed asset hit is cached immutable"
else
  bad "hashed asset hit Cache-Control is '$cc' (expected immutable)"
fi
miss="$(curl -s -o /dev/null -m 5 -D- "$B/command-center/assets/CeoMissionControlTab-BfGwQoxI.js")"
code="$(printf '%s' "$miss" | awk 'NR==1{print $2}')"
cc="$(printf '%s' "$miss" | awk 'tolower($1)=="cache-control:"{print tolower($0)}')"
[[ "$code" == "404" ]] && ok "missing hashed asset returns 404" || bad "missing hashed asset returned $code"
if grep -q 'immutable' <<<"$cc"; then
  bad "missing hashed asset is cached immutable ('$cc') — stale-chunk 404s would stick for a year"
elif grep -q 'no-store' <<<"$cc"; then
  ok "missing hashed asset is no-store"
else
  bad "missing hashed asset Cache-Control is '$cc' (expected no-store, must not be immutable)"
fi

# ── Security headers on API responses ───────────────────────────────────────────
hdrs="$(curl -s -o /dev/null -m 5 -D- "$B/api/health")"
for h in "x-content-type-options" "x-frame-options" "referrer-policy"; do
  if grep -qi "^$h:" <<<"$hdrs"; then ok "API response carries $h"; else bad "API response is missing $h"; fi
done
# Each header exactly once — nginx `add_header` stacks on top of the upstream's own.
dupes="$(grep -ci '^x-content-type-options:' <<<"$hdrs")"
[[ "$dupes" == "1" ]] && ok "security headers are not duplicated" || bad "x-content-type-options appears $dupes times"

echo
printf 'Gateway contract: %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
