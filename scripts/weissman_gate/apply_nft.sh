#!/usr/bin/env bash
# Apply unified Gate policy JSON onto local nftables. Requires WEISSMAN_VNGFW_APPLY=1.
set -euo pipefail
POLICY="${1:-}"
if [[ -z "$POLICY" || ! -f "$POLICY" ]]; then
  echo "usage: $0 policy.json" >&2
  exit 2
fi
if [[ "${WEISSMAN_VNGFW_APPLY:-}" != "1" ]]; then
  echo "refusing: set WEISSMAN_VNGFW_APPLY=1" >&2
  exit 1
fi
python3 - "$POLICY" <<'PY'
import json, sys, re, subprocess, tempfile, os
policy = json.load(open(sys.argv[1]))
lines = [
    "table inet weissman_gate {",
    "  chain forward {",
    "    type filter hook forward priority 0; policy drop;",
]
cidr_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
for r in policy.get("rules") or []:
    action = {"allow": "accept", "accept": "accept", "drop": "drop", "reject": "reject"}.get(str(r.get("action", "drop")).lower())
    proto = str(r.get("proto", "tcp")).lower()
    if proto not in ("tcp", "udp") or action is None:
        continue
    try:
        dport = int(r.get("dport") or 0)
    except (TypeError, ValueError):
        continue
    if not 1 <= dport <= 65535:
        continue
    saddr = str(r.get("saddr") or "0.0.0.0/0")
    if not cidr_re.match(saddr):
        continue
    lines.append(f"    ip saddr {saddr} {proto} dport {dport} {action}")
if str(policy.get("default_action") or "allow").lower() == "allow":
    lines.append("    accept")
lines += ["  }", "}"]
text = "\n".join(lines) + "\n"
path = os.path.join(tempfile.gettempdir(), "weissman_gate.nft")
open(path, "w").write(text)
subprocess.call(["nft", "delete", "table", "inet", "weissman_gate"])
r = subprocess.call(["nft", "-f", path])
sys.exit(r)
PY
