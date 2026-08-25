#!/usr/bin/env bash
# Docker daemon bring-up, shared by start_weissman.sh and start_weissman_live.sh.
# Sourced, never executed.
#
# Both launchers used to treat "docker info failed" as a dead end and told the operator to go
# start the daemon themselves — which is the one thing a launcher can do for them. A stopped
# daemon is a solvable state, and on a host that has already run this stack it is the ONLY
# thing standing between `./start_weissman.sh` and a running system.
#
# Contract for callers:
#   weissman_docker_ensure   -> 0 when a daemon answers (starting it if necessary)
#   "${WEISSMAN_DOCKER[@]}"  -> the invocation that works, which may be `sudo -n docker`
#
# Callers must go through that array rather than a bare `docker`: when the daemon is alive but
# its socket is not readable by this user — the state right after installing Docker, before
# `usermod -aG docker` and a re-login — sudo is the difference between working and "cannot
# connect to the Docker daemon".

WEISSMAN_DOCKER=(docker)
WEISSMAN_DOCKER_START_METHOD=""
WEISSMAN_DOCKERD_LOG="${WEISSMAN_DOCKERD_LOG:-/tmp/weissman-dockerd.log}"

# Use the caller's logging when it has some, so output keeps one voice per launcher.
_wd_log() {
  if declare -F log >/dev/null 2>&1; then log "$@"; else printf '[weissman] %s\n' "$*"; fi
}
_wd_warn() {
  if declare -F warn >/dev/null 2>&1; then warn "$@"; else printf '[weissman] WARN: %s\n' "$*" >&2; fi
}
_wd_have() { command -v "$1" >/dev/null 2>&1; }

# Run one command as root. Prompts only on a terminal — a non-interactive run (CI, systemd, an
# IDE task) must fail fast instead of blocking forever on an invisible password prompt.
weissman_sudo_run() {
  if [ "$(id -u)" = 0 ]; then "$@"; return; fi
  _wd_have sudo || return 1
  if sudo -n true 2>/dev/null; then sudo "$@"; return; fi
  if [ -t 0 ]; then
    _wd_log "sudo is required to: $*"
    sudo "$@"
    return
  fi
  return 1
}

# Does a daemon answer, and how do we reach it? Never prompts: `sudo -n` succeeds only with
# passwordless sudo or a still-valid timestamp from the daemon start below.
weissman_docker_responds() {
  if command docker info >/dev/null 2>&1; then
    WEISSMAN_DOCKER=(docker)
    return 0
  fi
  if [ "$(id -u)" != 0 ] && _wd_have sudo && sudo -n docker info >/dev/null 2>&1; then
    WEISSMAN_DOCKER=(sudo -n docker)
    return 0
  fi
  return 1
}

weissman_docker_start_daemon() {
  _wd_log "Docker daemon is not responding — starting it"
  if _wd_have systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^docker\.'; then
    weissman_sudo_run systemctl start docker.socket >/dev/null 2>&1 || true
    if weissman_sudo_run systemctl start docker >/dev/null 2>&1; then
      WEISSMAN_DOCKER_START_METHOD=systemctl
      return 0
    fi
    _wd_log "  systemctl could not start it — trying service(8)"
  fi
  if _wd_have service; then
    if weissman_sudo_run service docker start >/dev/null 2>&1; then
      WEISSMAN_DOCKER_START_METHOD=service
      return 0
    fi
    _wd_log "  service(8) could not start it — trying dockerd directly"
  fi
  if _wd_have dockerd; then
    # No usable init system (plain container images, some CI runners). AGENTS.md documents
    # `sudo dockerd &` for exactly this case. The log path travels in the environment so a path
    # containing a quote cannot break the command.
    _wd_log "  launching dockerd directly (log: ${WEISSMAN_DOCKERD_LOG})"
    if weissman_sudo_run env WEISSMAN_DOCKERD_LOG="$WEISSMAN_DOCKERD_LOG" \
         sh -c 'dockerd >>"$WEISSMAN_DOCKERD_LOG" 2>&1 &'; then
      WEISSMAN_DOCKER_START_METHOD=dockerd
      return 0
    fi
  fi
  return 1
}

weissman_docker_wait() {
  local deadline=$((SECONDS + ${1:-90}))
  while ((SECONDS < deadline)); do
    if weissman_docker_responds; then return 0; fi
    sleep 1
  done
  return 1
}

# 0 when Docker is usable. Starts the daemon when it is installed but down, unless
# WEISSMAN_DOCKER_AUTOSTART=0.
weissman_docker_ensure() {
  WEISSMAN_DOCKER_START_METHOD=""
  if ! _wd_have docker; then
    _wd_warn "Docker is not installed — install Docker 24+ with Compose v2: https://docs.docker.com/engine/install/"
    return 1
  fi
  if weissman_docker_responds; then
    if [ "${WEISSMAN_DOCKER[0]}" = sudo ]; then
      _wd_warn "Docker only answers through sudo — add yourself to the docker group to avoid it: sudo usermod -aG docker ${USER:-\$USER} && newgrp docker"
    fi
    _wd_log "Docker daemon is up"
    return 0
  fi
  if [ "${WEISSMAN_DOCKER_AUTOSTART:-1}" != 1 ]; then
    _wd_warn "Docker daemon is not responding and autostart is disabled"
    return 1
  fi
  if ! weissman_docker_start_daemon; then
    _wd_warn "could not start the Docker daemon (tried systemctl, service, dockerd)"
    return 1
  fi
  local began=$SECONDS
  if ! weissman_docker_wait "${WEISSMAN_DOCKER_WAIT:-90}"; then
    _wd_warn "Docker was started via ${WEISSMAN_DOCKER_START_METHOD} but never answered$([ "$WEISSMAN_DOCKER_START_METHOD" = dockerd ] && echo " (see ${WEISSMAN_DOCKERD_LOG})")"
    return 1
  fi
  _wd_log "Docker daemon is up (started via ${WEISSMAN_DOCKER_START_METHOD} in $((SECONDS - began))s)"
  return 0
}
