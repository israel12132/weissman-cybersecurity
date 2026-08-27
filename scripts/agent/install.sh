#!/usr/bin/env bash
# Weissman Endpoint Agent — single-command installer for Linux / macOS.
#
# Usage (paste from the dashboard):
#   curl -sSL https://<server>/install/agent.sh | WEISSMAN_TOKEN=... WEISSMAN_SERVER=https://<server> bash
#
# What this script does:
#   1. Verifies environment variables are present.
#   2. Picks the right binary for the host arch.
#   3. Downloads, verifies SHA-256, and installs to /opt/weissman/agent.
#   4. Creates a systemd unit (Linux) or launchd plist (macOS).
#   5. Performs initial enrollment using WEISSMAN_TOKEN, then starts the service.

set -euo pipefail

REQUIRED=("WEISSMAN_TOKEN" "WEISSMAN_SERVER")
for var in "${REQUIRED[@]}"; do
    if [ -z "${!var:-}" ]; then
        echo "[weissman-agent] Missing required env var: $var" >&2
        exit 1
    fi
done

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$ARCH" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) echo "[weissman-agent] unsupported arch '$ARCH'" >&2; exit 1 ;;
esac
case "$OS" in
    linux) PLATFORM="linux-${ARCH}-gnu" ;;
    darwin) PLATFORM="macos-${ARCH}" ;;
    *) echo "[weissman-agent] unsupported OS '$OS'" >&2; exit 1 ;;
esac

INSTALL_DIR=${WEISSMAN_INSTALL_DIR:-/opt/weissman}
BIN_DIR="${INSTALL_DIR}/agent"
BIN_PATH="${BIN_DIR}/weissman-agent"
mkdir -p "${BIN_DIR}"

BASE_URL="${WEISSMAN_SERVER%/}/install/binaries/${PLATFORM}"
echo "[weissman-agent] downloading ${BASE_URL}/weissman-agent"
if ! curl -sSL --fail "${BASE_URL}/weissman-agent" -o "${BIN_PATH}.tmp"; then
    echo "[weissman-agent] no agent binary published for platform '${PLATFORM}'." >&2
    echo "  The server image ships the binary for its own architecture only. To offer this" >&2
    echo "  platform, build it on the server (scripts/package_agent_binaries.sh cross-compiles" >&2
    echo "  all Linux targets) and place it at \$WEISSMAN_AGENT_BIN_DIR/${PLATFORM}/weissman-agent." >&2
    rm -f "${BIN_PATH}.tmp"
    exit 4
fi
EXPECTED_SHA=$(curl -sSL --fail "${BASE_URL}/weissman-agent.sha256" | awk '{print $1}')
ACTUAL_SHA=$(sha256sum "${BIN_PATH}.tmp" 2>/dev/null | awk '{print $1}')
if [ -z "${ACTUAL_SHA}" ]; then
    ACTUAL_SHA=$(shasum -a 256 "${BIN_PATH}.tmp" | awk '{print $1}')
fi
if [ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]; then
    echo "[weissman-agent] SHA-256 mismatch (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA})" >&2
    rm -f "${BIN_PATH}.tmp"
    exit 2
fi

SIG_TMP="${BIN_PATH}.sig.tmp"
if curl -sSL --fail "${BASE_URL}/weissman-agent.sig" -o "${SIG_TMP}" 2>/dev/null; then
    if ! command -v cosign >/dev/null 2>&1; then
        echo "[weissman-agent] signature present but cosign is not installed" >&2
        rm -f "${BIN_PATH}.tmp" "${SIG_TMP}"
        exit 6
    fi
    PUB="${WEISSMAN_COSIGN_PUB:-${COSIGN_PUBLIC_KEY:-}}"
    if [ -z "${PUB}" ]; then
        echo "[weissman-agent] signature present but WEISSMAN_COSIGN_PUB is unset" >&2
        rm -f "${BIN_PATH}.tmp" "${SIG_TMP}"
        exit 6
    fi
    if ! cosign verify-blob --key "${PUB}" --signature "${SIG_TMP}" "${BIN_PATH}.tmp"; then
        echo "[weissman-agent] cosign verify-blob failed" >&2
        rm -f "${BIN_PATH}.tmp" "${SIG_TMP}"
        exit 6
    fi
    mv "${SIG_TMP}" "${BIN_PATH}.sig"
    echo "[weissman-agent] cosign signature verified"
elif [ "${WEISSMAN_REQUIRE_COSIGN:-}" = "1" ]; then
    echo "[weissman-agent] WEISSMAN_REQUIRE_COSIGN=1 but no weissman-agent.sig was published" >&2
    rm -f "${BIN_PATH}.tmp"
    exit 6
fi

mv "${BIN_PATH}.tmp" "${BIN_PATH}"
chmod 0755 "${BIN_PATH}"

# Enroll ONCE, here, and persist the identity for the service to reuse.
#
# This step used to be a throwaway "verify it can enroll" check: it consumed the strictly
# single-use enrollment token and then wrote the SAME token into agent.env as the service
# credential. With Restart=always, systemd would start the agent, the agent would re-enroll with
# the now-consumed token, get HTTP 401 and exit — every 5 seconds, forever, while the installer
# printed "installed and started" and "online". No agent has ever successfully enrolled.
#
# The agent now writes ${INSTALL_DIR}/agent.state (0600) containing its agent id and long-lived
# renewal secret, and prefers that over the token on every subsequent start. The token is a
# bootstrap, used exactly once, which is what "single-use" was always supposed to mean.
export WEISSMAN_AGENT_STATE_FILE="${INSTALL_DIR}/agent.state"
if [ -n "${WEISSMAN_AGENT_TLS_PIN_SHA256:-}" ]; then
    export WEISSMAN_AGENT_TLS_PIN_SHA256
elif [[ "${WEISSMAN_SERVER}" == https://* ]]; then
    export WEISSMAN_AGENT_ALLOW_UNPINNED="${WEISSMAN_AGENT_ALLOW_UNPINNED:-1}"
fi
ENROLL_OUT=$("${BIN_PATH}" \
    --server-url "${WEISSMAN_SERVER}" \
    --enrollment-token "${WEISSMAN_TOKEN}" \
    --enroll-only 2>/dev/null || true)
if [ -z "${ENROLL_OUT}" ]; then
    echo "[weissman-agent] enrollment failed (check token + WEISSMAN_SERVER)" >&2
    exit 3
fi
if [ ! -s "${WEISSMAN_AGENT_STATE_FILE}" ]; then
    echo "[weissman-agent] enrolled but no state file was written to ${WEISSMAN_AGENT_STATE_FILE};" >&2
    echo "[weissman-agent] the service would re-enroll with a consumed token and crash-loop. Aborting." >&2
    exit 4
fi
chmod 600 "${WEISSMAN_AGENT_STATE_FILE}" 2>/dev/null || true

ENV_FILE="${INSTALL_DIR}/agent.env"
umask 077
# The token is retained only as a fallback for the case where agent.state is lost; the agent
# prefers the state file and will not touch the token while that exists. WEISSMAN_AGENT_STATE_FILE
# must be present here or the service would look for state next to the binary and, not finding it,
# fall back to the consumed token.
{
  echo "WEISSMAN_SERVER_URL=${WEISSMAN_SERVER}"
  echo "WEISSMAN_AGENT_STATE_FILE=${INSTALL_DIR}/agent.state"
  echo "WEISSMAN_AGENT_SPOOL_FILE=${INSTALL_DIR}/agent.spool.jsonl"
  echo "WEISSMAN_AGENT_KILL_FILE=${INSTALL_DIR}/agent.killed"
  echo "WEISSMAN_ENROLLMENT_TOKEN=${WEISSMAN_TOKEN}"
  echo "RUST_LOG=info"
  if [ -n "${WEISSMAN_AGENT_TLS_PIN_SHA256:-}" ]; then
    echo "WEISSMAN_AGENT_TLS_PIN_SHA256=${WEISSMAN_AGENT_TLS_PIN_SHA256}"
  elif [[ "${WEISSMAN_SERVER}" == https://* ]]; then
    echo "WEISSMAN_AGENT_ALLOW_UNPINNED=${WEISSMAN_AGENT_ALLOW_UNPINNED:-1}"
  fi
} > "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

if [ "${OS}" = "linux" ]; then
    UNIT=/etc/systemd/system/weissman-agent.service
    cat > "${UNIT}" <<UNIT_EOF
[Unit]
Description=Weissman Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
# ProtectSystem=strict mounts the entire filesystem read-only, so without this the agent cannot
# write agent.state. The installer pre-writes it, but if it is ever lost the agent must be able to
# re-enroll and persist — otherwise it would consume a fresh token on every single start and
# crash-loop again, which is the failure this whole change removes.
ReadWritePaths=${INSTALL_DIR}
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload
    systemctl enable --now weissman-agent.service
    echo "[weissman-agent] installed and started via systemd"
elif [ "${OS}" = "darwin" ]; then
    PLIST=/Library/LaunchDaemons/io.weissman.agent.plist
    cat > "${PLIST}" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.weissman.agent</string>
<key>ProgramArguments</key><array><string>${BIN_PATH}</string></array>
<key>EnvironmentVariables</key><dict>
<key>WEISSMAN_SERVER_URL</key><string>${WEISSMAN_SERVER}</string>
<key>WEISSMAN_ENROLLMENT_TOKEN</key><string>${WEISSMAN_TOKEN}</string>
</dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
PLIST_EOF
    launchctl unload "${PLIST}" 2>/dev/null || true
    launchctl load -w "${PLIST}"
    echo "[weissman-agent] installed and started via launchd"
fi

echo "[weissman-agent] online — verify in the dashboard under Agents."
