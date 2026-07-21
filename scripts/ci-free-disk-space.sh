#!/usr/bin/env bash
# Reclaim disk on GitHub-hosted ubuntu runners before Rust builds.
#
# The workspace pulls ~250 AWS-SDK + crypto crates. Compiling and, above all,
# LINKING weissman-server / weissman-worker against that many object files ran
# the runner out of disk mid-link — surfacing as `collect2: ld terminated with
# signal 7 (Bus error)` (an mmap failure once the filesystem is full), not a
# compile error. The default runner image ships ~25-30 GB of toolchains we never
# use (dotnet, Android SDK, GHC/Haskell, CodeQL bundles). Removing them up front
# gives the Rust build the headroom it needs. Purely a disk-headroom step: it
# changes no build inputs, thresholds, or gates.
#
# Every removal is best-effort (`|| true`) so a future runner-image change that
# drops one of these paths can never fail the build.
set -uo pipefail

echo "=== disk before cleanup ==="
df -h / || true

# Large preinstalled toolchains unused by this workspace.
sudo rm -rf /usr/share/dotnet || true
sudo rm -rf /usr/local/lib/android || true
sudo rm -rf /opt/ghc /usr/local/.ghcup || true
sudo rm -rf /opt/hostedtoolcache/CodeQL || true
sudo rm -rf /usr/local/share/powershell || true
sudo rm -rf /usr/local/share/chromium /usr/local/share/chrome_driver || true
sudo rm -rf /usr/share/swift || true

# Prune any preinstalled Docker images. Jobs that need images build them later;
# this only clears the base cache the runner ships with. Skip cleanly if docker
# is absent.
if command -v docker >/dev/null 2>&1; then
  sudo docker image prune --all --force || true
fi

echo "=== disk after cleanup ==="
df -h / || true
