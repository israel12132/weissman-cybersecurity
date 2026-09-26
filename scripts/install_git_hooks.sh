#!/usr/bin/env bash
# scripts/install_git_hooks.sh — point this clone at the repo's versioned hooks (.githooks/).
# Idempotent; run once per clone (start_weissman.sh also calls it when run from a checkout).
set -euo pipefail
ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
git -C "$ROOT" config core.hooksPath .githooks
chmod +x "$ROOT"/.githooks/* 2>/dev/null || true
echo "git hooks installed: core.hooksPath=.githooks ($(ls "$ROOT/.githooks" | tr '\n' ' '))"
