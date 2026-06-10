#!/usr/bin/env bash
# Fail when fingerprint_engine/migrations/ and crates/weissman-db/migrations/ drift.
# Compares filenames and SQL body (comments stripped). Comment-only diffs are ignored.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEFT="${ROOT}/fingerprint_engine/migrations"
RIGHT="${ROOT}/crates/weissman-db/migrations"

if [[ ! -d "$LEFT" ]]; then
  echo "error: missing directory: $LEFT" >&2
  exit 1
fi
if [[ ! -d "$RIGHT" ]]; then
  echo "error: missing directory: $RIGHT" >&2
  exit 1
fi

python3 - "$LEFT" "$RIGHT" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

left_dir, right_dir = Path(sys.argv[1]), Path(sys.argv[2])

def sql_files(directory: Path) -> dict[str, Path]:
    return {p.name: p for p in sorted(directory.glob("*.sql"))}

def strip_sql_comments(text: str) -> str:
    """Remove -- line comments and /* */ block comments."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_block = False
    while i < n:
        if in_block:
            end = text.find("*/", i)
            if end == -1:
                break
            i = end + 2
            in_block = False
            continue
        if text.startswith("/*", i):
            in_block = True
            i += 2
            continue
        if text.startswith("--", i):
            nl = text.find("\n", i)
            if nl == -1:
                break
            i = nl + 1
            continue
        out.append(text[i])
        i += 1
    normalized = "".join(out)
    lines = [re.sub(r"\s+", " ", line).strip() for line in normalized.splitlines()]
    return "\n".join(line for line in lines if line)

def body_hash(path: Path) -> str:
    return hashlib.sha256(strip_sql_comments(path.read_text(encoding="utf-8")).encode()).hexdigest()

left = sql_files(left_dir)
right = sql_files(right_dir)
errors: list[str] = []
notes: list[str] = []

only_left = sorted(set(left) - set(right))
only_right = sorted(set(right) - set(left))
for name in only_left:
    errors.append(f"missing in crates/weissman-db/migrations: {name}")
for name in only_right:
    errors.append(f"missing in fingerprint_engine/migrations: {name}")

for name in sorted(set(left) & set(right)):
    left_raw = left[name].read_text(encoding="utf-8")
    right_raw = right[name].read_text(encoding="utf-8")
    if left_raw == right_raw:
        continue
    if body_hash(left[name]) == body_hash(right[name]):
        notes.append(f"comment-only drift (ignored): {name}")
        continue
    errors.append(f"SQL body differs (beyond comments): {name}")

if notes:
    print("migration sync notes:")
    for note in notes:
        print(f"  - {note}")

if errors:
    print("migration sync FAILED:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    print(
        "\nKeep fingerprint_engine/migrations/ and crates/weissman-db/migrations/ "
        "in sync (same filenames and SQL body).",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"migration sync OK: {len(left)} files matched "
    f"({left_dir.relative_to(left_dir.parent.parent)} ↔ {right_dir.relative_to(right_dir.parent.parent)})"
)
PY
