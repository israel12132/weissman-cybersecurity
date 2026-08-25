#!/usr/bin/env bash
# Upsert deploy/env.max-power.env into a gitignored env file (does not remove secrets).
# Usage: ./scripts/apply_max_power_env.sh [.env]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRAG="$ROOT/deploy/env.max-power.env"
DEST="${1:-$ROOT/.env}"
if [[ ! -f "$FRAG" ]]; then
  echo "missing $FRAG" >&2
  exit 1
fi
if [[ ! -f "$DEST" ]]; then
  if [[ -f "$ROOT/.env.example" && "$DEST" == "$ROOT/.env" ]]; then
    cp "$ROOT/.env.example" "$DEST"
  else
    mkdir -p "$(dirname "$DEST")"
    : >"$DEST"
  fi
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

vals = parse_kv(frag_path.read_text())
text = dest_path.read_text() if dest_path.exists() else ""
lines = text.splitlines()
seen: set[str] = set()
out: list[str] = []
for line in lines:
    if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
        out.append(line)
        continue
    k = line.split("=", 1)[0]
    if k in vals:
        out.append(f"{k}={vals[k]}")
        seen.add(k)
    else:
        out.append(line)
missing = [k for k in vals if k not in seen]
if missing:
    if out and out[-1].strip():
        out.append("")
    out.append("# --- MAX POWER (from deploy/env.max-power.env) ---")
    for k in missing:
        out.append(f"{k}={vals[k]}")
dest_path.write_text("\n".join(out) + "\n")
print(f"updated {dest_path} ({len(vals)} max-power keys)")
PY
chmod 600 "$DEST"
echo "done. restart weissman-server and weissman-worker to apply."
