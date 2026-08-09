#!/usr/bin/env bash
# Contract tests for the production launcher (start_weissman_live.sh).
#
# WHY THIS EXISTS
# Nothing in CI executes start_weissman_live.sh, so two launch-blocking regressions shipped
# unnoticed: a stray `shift` that ate the first CLI flag (so the documented
# `--url https://your.domain` died with "unknown flag"), and a production secret
# (WEISSMAN_JOB_ORCHESTRATOR_SECRET) that the launcher never generated, so the server and
# worker failed closed at boot and the deploy timed out after 15 minutes.
#
# These checks are static + stubbed: no Docker daemon, no containers, no network, and they
# never write to a real .env. Safe to run anywhere, including CI.
#
#   ./scripts/test_launcher_contract.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LAUNCHER=start_weissman_live.sh
PASS=0
FAIL=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ─────────────────────────────────────────────────────────────────────────────
head_ "1. Shell syntax"
for f in "$LAUNCHER" start_weissman.sh start_weissman_rust.sh scripts/sync_monitoring_admin.sh; do
  if bash -n "$f" 2>/dev/null; then ok "$f parses"; else bad "$f has a syntax error"; fi
done

# ─────────────────────────────────────────────────────────────────────────────
head_ "2. CLI flag contract (regression guard for the swallowed-first-flag bug)"
# Stub docker so the run dies in check_prereqs — which happens AFTER parse_args but BEFORE
# ensure_env, so a real .env is never read or written.
STUB="$(mktemp -d)"
trap 'rm -rf "$STUB"' EXIT
cat >"$STUB/docker" <<'STUBEOF'
#!/bin/bash
[ "$1" = "compose" ] && [ "$2" = "version" ] && exit 0
[ "$1" = "info" ] && exit 1     # -> "Docker daemon not running", i.e. we got past parse_args
exit 0
STUBEOF
chmod +x "$STUB/docker"

assert_flag_accepted() {
  local desc="$1"; shift
  local out
  out="$(PATH="$STUB:$PATH" bash "$LAUNCHER" "$@" 2>&1 || true)"
  if grep -q "unknown flag" <<<"$out"; then
    bad "$desc — rejected: $(grep -m1 'unknown flag' <<<"$out")"
  else
    ok "$desc"
  fi
}

assert_flag_accepted "--url <origin>"                    --url https://sec.example.com
assert_flag_accepted "start --url <origin>"        start --url https://sec.example.com
assert_flag_accepted "--email <addr>"                    --email admin@example.com
assert_flag_accepted "--no-monitoring"                   --no-monitoring
assert_flag_accepted "--no-build"                        --no-build
assert_flag_accepted "--no-build then --url"             --no-build --url https://sec.example.com
assert_flag_accepted "--no-monitoring then --no-build"   --no-monitoring --no-build
assert_flag_accepted "(no arguments)"

# A genuinely bogus flag must still be rejected — otherwise the check above proves nothing.
# Capture first: the launcher exits non-zero here (correctly), and `pipefail` would make a
# `... | grep` pipeline report that exit status rather than whether the text matched.
bogus_out="$(PATH="$STUB:$PATH" bash "$LAUNCHER" --definitely-not-a-flag 2>&1 || true)"
if grep -q "unknown flag" <<<"$bogus_out"; then
  ok "bogus flag is still rejected"
else
  bad "bogus flag was accepted — argument validation is not running"
fi

# --help must render the usage block, not shell source lines.
help_out="$(PATH="$STUB:$PATH" bash "$LAUNCHER" --help 2>&1 || true)"
if grep -q -- "--no-monitoring" <<<"$help_out" && ! grep -q "set -euo pipefail" <<<"$help_out"; then
  ok "--help prints usage without leaking script source"
else
  bad "--help output is wrong (missing flags, or leaking 'set -euo pipefail')"
fi

# Every flag the header documents must actually be implemented.
while read -r flag; do
  if grep -qE "^[[:space:]]+(-[a-z]\|)?${flag}\)" "$LAUNCHER"; then
    ok "documented flag $flag is implemented"
  else
    bad "documented flag $flag has no case branch"
  fi
done < <(sed -n '/^Flags (start only):/,/^$/p' "$LAUNCHER" | grep -oE '^\s+--[a-z-]+' | tr -d ' ')

# ─────────────────────────────────────────────────────────────────────────────
head_ "3. Secret contract — every compose-required var must be produced by the launcher"
# docker-compose.prod.yml marks each mandatory secret as ${VAR:?message}. If the launcher
# does not create it, `compose up` (or the app's own startup guard) fails on a clean host.
# Skip comment lines: the prod overlay's header documents the `${VAR:?message}` idiom, and
# a naive scan would treat the literal placeholder "VAR" as a required secret.
mapfile -t required < <(
  grep -hv '^[[:space:]]*#' docker-compose.yml docker-compose.prod.yml \
    | grep -ohE '\$\{[A-Z_]+:\?' \
    | sed -E 's/^\$\{([A-Z_]+):\?$/\1/' | sort -u
)
if ((${#required[@]} == 0)); then
  bad "found no \${VAR:?} entries — the parser is broken, not the compose files"
fi
# Operator-supplied secrets: required only inside an opt-in profile (e.g. the `oast`
# service's WEISSMAN_OAST_DOMAIN is a DNS zone the operator delegates, not something the
# launcher can invent). They must be documented in the template (section 6) but are not
# generated.
OPERATOR_SUPPLIED=" WEISSMAN_OAST_DOMAIN "
for var in "${required[@]}"; do
  if [[ "$OPERATOR_SUPPLIED" == *" $var "* ]]; then
    ok "$var is operator-supplied (opt-in profile) — not auto-generated by design"
    continue
  fi
  # Produced either by the generated-secrets array or by an explicit env_set call.
  if grep -qE "^[[:space:]]*${var}$" "$LAUNCHER" || grep -qE "env_set ${var}\b" "$LAUNCHER"; then
    ok "$var is generated/set by the launcher"
  else
    bad "$var is REQUIRED by compose but the launcher never generates it"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
head_ "4. Server/worker parity — secrets the worker's own startup guard demands"
# security_startup.rs checks these outside the Server-only scope, so weissman-worker
# enforces them too. A var wired only into `backend:` makes the worker crash-loop.
for var in WEISSMAN_JWT_SECRET WEISSMAN_JOB_ORCHESTRATOR_SECRET; do
  for file in docker-compose.yml docker-compose.prod.yml; do
    # Count occurrences after the worker: key, before the next top-level service.
    if sed -n '/^  worker:/,/^  [a-z]/p' "$file" | grep -q "${var}:"; then
      ok "$var reaches the worker in $file"
    else
      bad "$var missing from the worker environment in $file"
    fi
  done
done

# ─────────────────────────────────────────────────────────────────────────────
head_ "5. Bind-mount contract — a missing host path becomes a DIRECTORY, not a file"
# Docker materialises an absent bind source as an empty directory. For a mount that should
# be a config FILE, the container then gets a directory and refuses to start.
GENERATED_AT_PREFLIGHT=(monitoring/prometheus-web.generated.yml)
mapfile -t mounts < <(
  grep -oE '^\s+- \./[^:]+:[^:]+' docker-compose.yml | sed -E 's/^\s+- \.\/([^:]+):.*/\1/' | sort -u
)
for m in "${mounts[@]}"; do
  if [[ -e "$m" ]]; then
    ok "$m exists in the tree"
  elif printf '%s\n' "${GENERATED_AT_PREFLIGHT[@]}" | grep -qx "$m"; then
    # Must be created BEFORE `compose up`, i.e. from the preflight step — not from the
    # banner, which runs after the containers are already up.
    if grep -q "preflight_monitoring" "$LAUNCHER" \
       && sed -n '/^cmd_start()/,/^}/p' "$LAUNCHER" | grep -B99 'compose_up' | grep -q 'preflight_monitoring'; then
      ok "$m is generated during preflight, before compose_up"
    else
      bad "$m is generated, but not before compose_up — Docker will create a directory in its place"
    fi
  else
    bad "$m is bind-mounted but absent and not generated at preflight"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
head_ "6. Template covers every compose-required secret"
# Each ${VAR:?} in the compose files must have a line in PRODUCTION.env.template, or the
# documented `cp PRODUCTION.env.template .env` + manual compose path dies at interpolation
# (this is how REDIS_PASSWORD was missing).
for var in "${required[@]}"; do
  # WEISSMAN_PUBLIC_BASE_URL is set from --url / a default by the launcher, but should also
  # be present in the template for the manual path.
  if grep -qE "^${var}=" PRODUCTION.env.template; then
    ok "$var present in PRODUCTION.env.template"
  else
    bad "$var is required by compose (\${${var}:?}) but absent from PRODUCTION.env.template"
  fi
done

# No duplicate keys: the launcher's env_get uses `tail -1`, so a second assignment of the
# same key silently wins. A stray WEISSMAN_OAST_DOMAIN=<vendor domain> lower in the file
# once overrode the intended blank and auto-enabled OAST against the wrong collector.
dupes="$(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' PRODUCTION.env.template | sort | uniq -d)"
if [[ -z "$dupes" ]]; then
  ok "PRODUCTION.env.template has no duplicate keys"
else
  bad "PRODUCTION.env.template has duplicate keys (last wins in env_get): $(tr '\n' ' ' <<<"$dupes")"
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "7. Production overlay renders (structure + interpolation)"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  # Synthetic env satisfying every ${VAR:?}; `config` needs no daemon.
  declare -a envassign=()
  for var in "${required[@]}"; do envassign+=("$var=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); done
  for var in POSTGRES_USER POSTGRES_DB DB_APP_USER DB_AUTH_USER DB_RO_USER WEISSMAN_ADMIN_EMAIL; do envassign+=("$var=weissman"); done
  if env "${envassign[@]}" docker compose -f docker-compose.yml -f docker-compose.prod.yml \
       --profile monitoring config >/dev/null 2>/tmp/compose_config_err; then
    ok "prod overlay renders (--profile monitoring)"
  else
    bad "prod overlay failed to render: $(tr '\n' ' ' </tmp/compose_config_err | head -c 200)"
  fi
  # The OAST profile adds the oast service (with its own ${VAR:?} vars) — validate it too.
  if env "${envassign[@]}" docker compose -f docker-compose.yml -f docker-compose.prod.yml \
       --profile monitoring --profile oast config >/dev/null 2>/tmp/compose_config_err; then
    ok "prod overlay renders (--profile monitoring --profile oast)"
  else
    bad "oast profile failed to render: $(tr '\n' ' ' </tmp/compose_config_err | head -c 200)"
  fi
else
  printf '  \033[33mSKIP\033[0m docker compose unavailable — overlay render not checked here (CI runs it)\n'
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "8. verify_live probes only unauthenticated, existing endpoints"
# /api/health has no "status" key (its success marker is "ok":true), and
# /api/config/public sits behind auth_guard (401 unauthenticated). Probing either fails
# every healthy deploy — lock both out.
vbody="$(sed -n '/^verify_live()/,/^}/p' "$LAUNCHER")"
if grep -q "grep -q '\"status\"'" <<<"$vbody"; then
  bad "verify_live still greps '\"status\"' — /api/health never returns that key"
else
  ok "verify_live does not assert the phantom '\"status\"' key"
fi
# Match an actual probe (a curl line), not an explanatory comment mentioning the path.
if grep -vE '^\s*#' <<<"$vbody" | grep -q "curl.*api/config/public"; then
  bad "verify_live probes /api/config/public — it requires auth and returns 401"
else
  ok "verify_live does not probe the auth-gated /api/config/public"
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "9. Health-gate contract"
# compose resolves service names against ENABLED profiles only, so any `compose ps` that
# names a monitoring service must pass --profile monitoring or it silently finds nothing.
if grep -qE '\bdc (ps|logs|up|down)' "$LAUNCHER" && ! grep -qE '"\$\{COMPOSE\[@\]\}" ps -q' "$LAUNCHER"; then
  ok "compose calls go through the profile-aware dc() helper"
else
  bad "a raw \${COMPOSE[@]} ps call bypasses --profile monitoring (profiled services will never be found)"
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "10. Monitoring & security posture invariants"
# Prometheus must be loopback-bound and must NOT expose the lifecycle API.
if grep -qE '"127\.0\.0\.1:9090:9090"' docker-compose.yml; then
  ok "Prometheus is published on loopback only"
else
  bad "Prometheus 9090 is not bound to 127.0.0.1 (unauthenticated metrics exposed on all interfaces)"
fi
# (skip comment lines so our own explanatory comments don't trip these checks)
if grep -vE '^\s*#' docker-compose.yml | grep -q -- "--web.enable-lifecycle"; then
  bad "Prometheus still has --web.enable-lifecycle (remote /-/quit and /-/reload)"
else
  ok "Prometheus lifecycle API is disabled"
fi
# Alertmanager config must not carry un-substituted \${...} placeholders (there is no envsubst step).
if grep -vE '^\s*#' monitoring/alertmanager.yml | grep -qE '\$\{[A-Z_]+\}'; then
  bad "alertmanager.yml has un-substituted \${...} placeholders — it will crash-loop on load"
else
  ok "alertmanager.yml has no un-substituted placeholders"
fi
# redis-exporter must authenticate under the prod overlay (Redis has requirepass).
if grep -A4 '^  redis-exporter:' docker-compose.prod.yml | grep -q 'REDIS_PASSWORD'; then
  ok "redis-exporter authenticates to Redis in the prod overlay"
else
  bad "redis-exporter has no REDIS_PASSWORD override — redis metrics will be dead under requirepass"
fi
# Backend must trust proxy headers (real client IP for rate limits / lockout / audit).
if sed -n '/^  backend:/,/^  [a-z]/p' docker-compose.prod.yml | grep -q 'WEISSMAN_TRUST_PROXY_HEADERS'; then
  ok "backend receives WEISSMAN_TRUST_PROXY_HEADERS"
else
  bad "backend is missing WEISSMAN_TRUST_PROXY_HEADERS — every client collapses into one rate-limit bucket"
fi
# The template must not ship a hardcoded public origin (it becomes every deploy's URL).
if grep -qE '^WEISSMAN_PUBLIC_BASE_URL=.+' PRODUCTION.env.template; then
  bad "PRODUCTION.env.template hardcodes WEISSMAN_PUBLIC_BASE_URL — leave it blank"
else
  ok "PRODUCTION.env.template ships WEISSMAN_PUBLIC_BASE_URL blank"
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "11. Feature wiring — Ask Weissman (NL->SQL) and OAST"
# The read-only role must be generated AND reach the backend, or /api/ask is 503 and the
# boot role-sync strips LOGIN from weissman_ro.
if grep -qE "^[[:space:]]*DB_RO_PASSWORD$" "$LAUNCHER"; then
  ok "launcher generates DB_RO_PASSWORD"
else
  bad "DB_RO_PASSWORD not generated — Ask Weissman (/api/ask) will be disabled"
fi
if sed -n '/^  backend:/,/^  [a-z]/p' docker-compose.prod.yml | grep -q 'WEISSMAN_READ_ONLY_DATABASE_URL'; then
  ok "backend receives WEISSMAN_READ_ONLY_DATABASE_URL (prod overlay)"
else
  bad "backend has no WEISSMAN_READ_ONLY_DATABASE_URL — Ask Weissman disabled"
fi
# OAST: the listener service must exist and the launcher must be able to enable its profile.
if grep -qE '^\s+oast:' docker-compose.prod.yml; then
  ok "oast listener service is defined in the prod overlay"
else
  bad "oast service missing from docker-compose.prod.yml — OAST engine can never confirm callbacks"
fi
if grep -q 'profile oast' "$LAUNCHER"; then
  ok "launcher can enable the oast profile"
else
  bad "launcher never enables the oast profile"
fi
# Backend must know where to correlate OAST callbacks.
if sed -n '/^  backend:/,/^  [a-z]/p' docker-compose.prod.yml | grep -q 'WEISSMAN_OAST_LISTENER_URL'; then
  ok "backend receives WEISSMAN_OAST_LISTENER_URL"
else
  bad "backend has no WEISSMAN_OAST_LISTENER_URL — engines cannot poll the listener"
fi
# OAST domain is operator-supplied but must be documented in the template, and blank.
if grep -qE '^WEISSMAN_OAST_DOMAIN=$' PRODUCTION.env.template; then
  ok "PRODUCTION.env.template documents WEISSMAN_OAST_DOMAIN (blank)"
else
  bad "WEISSMAN_OAST_DOMAIN missing/hardcoded in PRODUCTION.env.template"
fi
# The oast service must NOT use \${VAR:?} for its domain — Compose interpolates every
# service on `up`, so a :? there would abort the default (OAST-off) launch.
if sed -n '/^  oast:/,/^  [a-z#]/p' docker-compose.prod.yml | grep -q 'WEISSMAN_OAST_DOMAIN.*:?'; then
  bad "oast service uses \${WEISSMAN_OAST_DOMAIN:?} — breaks the default (OAST-off) up"
else
  ok "oast service does not hard-require WEISSMAN_OAST_DOMAIN via :? (default up stays green)"
fi

# ─────────────────────────────────────────────────────────────────────────────
head_ "12. Monitoring metric-label + persistence integrity"
# The HTTP metrics are labeled `path` in the Rust code; alerts/dashboards must not query a
# nonexistent `endpoint` label (that made the scan-latency alert match nothing).
labeldrift="$(grep -rlE 'http_request(s_total|_duration_seconds)[^}]*by \(le, endpoint\)|http_request(s_total|_duration_seconds)[^}]*\{endpoint|by \(endpoint\)' monitoring/ 2>/dev/null || true)"
if [[ -z "$labeldrift" ]]; then
  ok "no http_request_* query uses the nonexistent 'endpoint' label"
else
  bad "endpoint-label drift still present in: $(tr '\n' ' ' <<<"$labeldrift")"
fi
# Alertmanager must persist silences/notification log. Match the named data volume, not
# the read-only /etc/alertmanager config mounts.
if sed -n '/^  alertmanager:/,/^  [a-z]/p' docker-compose.yml | grep -qE 'weissman_alertmanager:/alertmanager\b' \
   && grep -qE '^  weissman_alertmanager:' docker-compose.yml; then
  ok "alertmanager has a declared persistent volume"
else
  bad "alertmanager has no persistent data volume — silences lost on restart"
fi
# wasm-bindgen-cli must be version-pinned for reproducible frontend builds.
if grep -q 'wasm-bindgen-cli.*--version' deploy/frontend.Dockerfile; then
  ok "wasm-bindgen-cli is version-pinned"
else
  bad "wasm-bindgen-cli is unpinned — schema-version drift can break the build"
fi

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
