# 12 — Endpoint Agent

## Purpose

Deploy, enroll, and operate the Weissman endpoint agent (`weissman-agent`) for on-host detections, UEBA, and ~45 **agent-required** engines that cannot run as remote probes.

---

## Prerequisites

- Operator role for token generation
- Agent binaries packaged (`scripts/package_agent_binaries.sh`)
- HTTPS `WEISSMAN_PUBLIC_BASE_URL` reachable from endpoints
- Firewall allows outbound WSS to platform
- Windows or Linux targets in authorized client scope

---

## Agent architecture

```
Endpoint host
  └─ weissman-agent process
       ├─ JWT role=agent (enrollment token)
       ├─ WebSocket telemetry → /ws/agent
       ├─ Local detections (UEBA, persistence, etc.)
       └─ Findings reported to server

Command Center Agent Management
  └─ Fleet status, token issue, install scripts
```

Agent JWT uses role **`agent`** — separate from human RBAC hierarchy (manual 07).

---

## Step-by-step: deploy agent

### 1. Create enrollment token

Command Center → **Agent Management** → **Generate Token**

Associate token with client and optional expiry. Token encodes tenant and client scope.

### 2. Linux install

One-liner from Agent Management UI or manual:

```bash
curl -sSL https://your-domain.example/install/agent.sh | \
  WEISSMAN_TOKEN="<enrollment-token>" \
  WEISSMAN_SERVER=https://your-domain.example \
  bash
```

Installer script: `scripts/agent/install.sh`, served at **`GET /install/agent.sh`**.

Downloads platform-specific binary from `/install/binaries/:platform/weissman-agent` with SHA256 verification (`/weissman-agent.sha256`).

### 3. Windows install

PowerShell (elevated):

```powershell
iwr https://your-domain.example/install/agent.ps1 | iex
Install-WeissmanAgent -Token "<enrollment-token>" -Server "https://your-domain.example"
```

Served at **`GET /install/agent.ps1`** (`scripts/agent/install.ps1`).

### 4. Verify fleet status

Agent Management dashboard shows:

- Hostname, OS, agent version
- Last seen timestamp
- Online/offline status

WebSocket heartbeat updates within seconds of successful connect.

### 5. Run agent-required engines

Once agent is **online**, agent-gated engine hubs unlock Run actions. UI empty states clear.

Engines return live host findings — memory artifacts, persistence mechanisms, local credential stores, etc.

---

## Packaging binaries for production

Before go-live, build and package all target platforms:

```bash
cargo build --release -p weissman-agent
bash scripts/package_agent_binaries.sh
```

Place artifacts where server can serve them under `/install/binaries/`.

Missing binary for an OS/arch causes install script failure — verify in manual **18** QA.

---

## Agent security

| Control | Detail |
|---------|--------|
| Enrollment tokens | Single-use or time-limited; revoke in UI |
| Transport | TLS to `WEISSMAN_PUBLIC_BASE_URL` |
| Auth | Agent JWT with `role=agent`; `require_agent` gate on fleet APIs |
| Scope | Agent bound to client; findings tagged accordingly |

Rotate compromised tokens immediately. Revoked agents cannot reconnect.

---

## Detections and UEBA

Agent collects:

- Process execution anomalies
- Persistence mechanism changes
- Network connection patterns
- Local security configuration drift

Findings merge into global Findings view with `engine_id` prefix indicating agent source.

Cross-reference with remote ASM findings for hybrid attack surface view.

---

## Fleet operations

| Task | Procedure |
|------|-----------|
| Upgrade agent | Re-run install script with new binary version |
| Decommission | Revoke token; uninstall service |
| Troubleshoot offline | Check outbound HTTPS/WSS; verify token not expired |
| Mass deploy | GPO/SCCM/Ansible distributing install one-liner |

---

## Verification

```bash
# Install script reachable
curl -sf https://your-domain.example/install/agent.sh | head -5

# Binary checksum endpoint
curl -sf https://your-domain.example/install/binaries/linux-amd64/weissman-agent.sha256

# API fleet list (operator cookie)
curl -sf -b cookies.txt https://your-domain.example/api/agents/fleet | jq '.agents | length'

# Agent-required engine after online
# Run engine → expect host findings, not empty state
```

Checklist:

- [ ] Agent shows online in UI
- [ ] At least one agent engine produces findings
- [ ] Findings attributed to correct client
- [ ] Revoked token cannot reconnect

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Install 404 | Run `package_agent_binaries.sh`; check gateway routes |
| SHA mismatch | Rebuild and republish binaries |
| Agent offline | Firewall blocking WSS; check `journalctl` on host |
| Empty agent engines | Agent not associated with client; token scope wrong |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [05-production-security](05-production-security.md)
- [18-qa-verification](18-qa-verification.md)
