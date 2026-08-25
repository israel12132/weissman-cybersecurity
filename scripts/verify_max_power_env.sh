#!/usr/bin/env bash
# Compare a destination env file against deploy/env.max-power.env.
# Usage: ./scripts/verify_max_power_env.sh [.env]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRAG="$ROOT/deploy/env.max-power.env"
DEST="${1:-$ROOT/.env}"
if [[ ! -f "$FRAG" ]]; then
  echo "missing $FRAG" >&2
  exit 1
fi
if [[ ! -f "$DEST" ]]; then
  echo "missing $DEST — run ./scripts/apply_max_power_env.sh first" >&2
  exit 1
fi
python3 - "$FRAG" "$DEST" <<'PY'
import sys
from pathlib import Path

frag_path, dest_path = Path(sys.argv[1]), Path(sys.argv[2])

def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out

want = parse_kv(frag_path.read_text())
have = parse_kv(dest_path.read_text())
missing = [k for k in want if k not in have]
mismatch = [k for k in want if k in have and have[k] != want[k]]
ok = [k for k in want if k in have and have[k] == want[k]]
print(f"max-power keys: {len(want)}")
print(f"matched: {len(ok)}")
print(f"missing: {len(missing)}")
print(f"mismatch: {len(mismatch)}")
if missing:
    print("MISSING " + " ".join(missing))
if mismatch:
    for k in mismatch:
        print(f"MISMATCH {k} want={want[k]!r} have={have[k]!r}")
if missing or mismatch:
    sys.exit(1)
print("ALL_MAX_POWER_KEYS_APPLIED")
PY
