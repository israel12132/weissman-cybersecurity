#!/usr/bin/env bash
# Align Grafana + Prometheus UI credentials with WEISSMAN_ADMIN_EMAIL / WEISSMAN_ADMIN_PASSWORD.
#
# `prometheus` MUST run BEFORE `docker compose up`: docker-compose.yml bind-mounts
# monitoring/prometheus-web.generated.yml into the Prometheus container. That file is
# gitignored, so on a fresh clone it does not exist and the Docker daemon silently creates
# a DIRECTORY in its place — after which Prometheus is handed a directory as its
# --web.config.file and refuses to start. Generating the file first keeps that from ever
# happening; see start_weissman_live.sh, which calls us during preflight.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Monitoring gets its OWN credential, not the platform super-admin one.
#
# This used to bcrypt WEISSMAN_ADMIN_PASSWORD into the Prometheus basic-auth file, so the
# password guarding the observability stack was byte-identical to the Weissman platform
# super-admin password. Prometheus and Grafana are third-party services with their own CVE
# streams and their own exposed logins; a disclosure in either handed over the platform.
# MONITORING_BASIC_AUTH_PASSWORD is generated once and persisted to .env.
EMAIL="${MONITORING_BASIC_AUTH_USER:-weissman-monitoring}"
PASSWORD="${MONITORING_BASIC_AUTH_PASSWORD:-}"
WEB_CONFIG="${ROOT}/monitoring/prometheus-web.generated.yml"
# Prometheus scrapes its own /metrics, and --web.config.file gates *every* endpoint including
# that one — so the self-scrape needs the plaintext to authenticate to itself. It lives in a
# 0600 file rather than in prometheus.yml so the secret is not in a committed config.
PASSWORD_FILE="${ROOT}/monitoring/prometheus-scrape-password.generated"

if [[ -z "$PASSWORD" ]]; then
  if [[ -f "${ROOT}/.env" ]] && grep -q '^MONITORING_BASIC_AUTH_PASSWORD=' "${ROOT}/.env"; then
    echo "MONITORING_BASIC_AUTH_PASSWORD is present in .env but empty — set it or remove the line" >&2
    exit 1
  fi
  PASSWORD="$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)"
  printf '\nMONITORING_BASIC_AUTH_USER=%s\nMONITORING_BASIC_AUTH_PASSWORD=%s\n' \
    "$EMAIL" "$PASSWORD" >> "${ROOT}/.env"
  echo "Generated MONITORING_BASIC_AUTH_PASSWORD and appended it to .env"
fi

# Compose derives the project name from COMPOSE_PROJECT_NAME, else from the directory
# basename (lowercased, stripped to [a-z0-9_-]). Hardcoding a container name breaks for
# anyone who clones into a differently-named directory, so resolve it by compose labels.
compose_project() {
  if [[ -n "${COMPOSE_PROJECT_NAME:-}" ]]; then
    printf '%s' "$COMPOSE_PROJECT_NAME"
    return
  fi
  basename "$ROOT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g'
}

# Echo the container ID for a compose service, or nothing when it is not running.
find_service_container() {
  local service="$1" project cid
  project="$(compose_project)"

  cid="$(docker ps -q \
    --filter "label=com.docker.compose.project=${project}" \
    --filter "label=com.docker.compose.service=${service}" 2>/dev/null | head -1)"
  if [[ -n "$cid" ]]; then
    printf '%s' "$cid"
    return
  fi

  # Fall back to the service label alone — correct when exactly one such container runs.
  local matches
  matches="$(docker ps -q --filter "label=com.docker.compose.service=${service}" 2>/dev/null)"
  if [[ "$(printf '%s\n' "$matches" | grep -c .)" == "1" ]]; then
    printf '%s' "$matches"
    return
  fi

  # Explicit operator override, for stacks not managed by compose.
  local override_var override
  override_var="WEISSMAN_$(printf '%s' "$service" | tr '[:lower:]-' '[:upper:]_')_CONTAINER"
  override="${!override_var:-}"
  if [[ -n "$override" ]] && docker ps --format '{{.Names}}' | grep -qx "$override"; then
    printf '%s' "$override"
  fi
}

# bcrypt the admin password for Prometheus basic auth. Prefer a local htpasswd (works
# offline); fall back to the httpd image only when the host has no apache2-utils.
# The password is piped via STDIN (`-i`), never passed on the command line — argv is
# visible in /proc/<pid>/cmdline and, for `docker run`, recorded by the daemon.
bcrypt_htpasswd_line() {
  if command -v htpasswd >/dev/null 2>&1; then
    printf '%s' "$PASSWORD" | htpasswd -niBC 12 "$EMAIL"
  else
    printf '%s' "$PASSWORD" | docker run --rm -i httpd:2.4-alpine htpasswd -niBC 12 "$EMAIL"
  fi
}

gen_prometheus_web_config() {
  # A previous `docker compose up` with the file absent leaves a directory here; the write
  # below would fail with "Is a directory" and (when called with `|| true`) be swallowed.
  if [[ -d "$WEB_CONFIG" ]]; then
    rmdir "$WEB_CONFIG" 2>/dev/null || {
      echo "ERROR: ${WEB_CONFIG} is a non-empty directory (created by a previous docker run with the file missing). Remove it and re-run." >&2
      return 1
    }
    echo "Removed stray directory at ${WEB_CONFIG}"
  fi

  # bcrypt_htpasswd_line() feeds the password over stdin (-i), never as an argv element:
  # an argv password is visible to every local user via `ps aux` and is recorded in the
  # Docker daemon's container config (`docker inspect`) and `docker events`.
  local line hash
  line="$(bcrypt_htpasswd_line)"
  hash="${line#*:}"
  if [[ -z "$hash" || "$hash" == "$line" ]]; then
    echo "ERROR: could not compute a bcrypt hash for the Prometheus basic-auth user" >&2
    return 1
  fi

  mkdir -p "$(dirname "$WEB_CONFIG")"
  # Quote the username: an email is a YAML key here and ':' / '@' would otherwise be
  # parsed as structure rather than text.
  cat >"$WEB_CONFIG" <<EOF
# Generated by scripts/sync_monitoring_admin.sh — do not commit.
basic_auth_users:
  "${EMAIL}": "${hash}"
EOF
  # World-readable on purpose: the file is bind-mounted read-only into the Prometheus
  # container, which runs as an unprivileged uid that does not match the host owner.
  # It holds a bcrypt hash, never the plaintext password.
  chmod 644 "$WEB_CONFIG"
  echo "Wrote ${WEB_CONFIG}"

  # Plaintext copy for Prometheus's own self-scrape (basic_auth password_file in
  # monitoring/prometheus.yml). 0644 for the same reason as above — the container runs as an
  # unprivileged uid that does not match the host owner — but this one holds the plaintext, so
  # it is gitignored and must never be committed.
  umask 022
  printf '%s' "$PASSWORD" > "$PASSWORD_FILE"
  chmod 644 "$PASSWORD_FILE"
  echo "Wrote ${PASSWORD_FILE}"

  # If Prometheus is already running it started without (or with a stale) web config;
  # it only re-reads --web.config.file that was present at launch, so restart it.
  local cid
  cid="$(find_service_container prometheus)"
  if [[ -n "$cid" ]]; then
    docker restart "$cid" >/dev/null
    echo "Restarted Prometheus to pick up the new web config"
  fi
}

sync_grafana_password() {
  local cid
  cid="$(find_service_container grafana)"
  if [[ -z "$cid" ]]; then
    echo "Grafana container not running — skip CLI reset"
    return 0
  fi
  # Pass the password via the environment (docker reads GF_PASS from its own env
  # when `-e GF_PASS` is given with no value), so it never appears on the argv
  # that `ps aux` / `docker inspect` expose.
  GF_PASS="$PASSWORD" docker exec -e GF_PASS "$cid" \
    sh -c 'grafana-cli admin reset-admin-password "$GF_PASS"' >/dev/null
  # GF_SECURITY_ADMIN_USER (docker-compose.prod.yml) names the admin login on a FRESH
  # Grafana volume; on an existing volume the original login is kept and only the
  # password is reset here. Report what Grafana actually has so the banner cannot lie.
  local login
  login="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" \
             | sed -n 's/^GF_SECURITY_ADMIN_USER=//p' | head -1)"
  echo "Grafana admin password synced (login: ${login:-admin})"
}

case "${1:-all}" in
  prometheus)
    gen_prometheus_web_config
    ;;
  grafana)
    sync_grafana_password
    ;;
  all)
    gen_prometheus_web_config
    sync_grafana_password
    ;;
  *)
    echo "Usage: $0 [all|grafana|prometheus]" >&2
    exit 1
    ;;
esac
