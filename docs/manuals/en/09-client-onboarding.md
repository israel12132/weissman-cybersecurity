# 09 — Client Onboarding

## Purpose

Onboard authorized client organizations into Weissman for legitimate security assessments. Covers legal prerequisites, scope definition, first scan, and emergency procedures.

**Critical:** Only onboard clients with **explicit written authorization** for security testing.

---

## Prerequisites

- Operator role or higher
- Active billing subscription (when `WEISSMAN_BILLING_STRICT=1`)
- Signed MSA/SOW with authorized scope
- Platform healthy (manual 18 QA passed)
- Emergency contacts documented

---

## Pre-onboarding checklist

### Legal and authorization

- [ ] Signed Master Service Agreement (MSA) or Statement of Work (SOW)
- [ ] Explicit authorization letter from client
- [ ] Authorized scope documented (domains, IPs, applications)
- [ ] Exclusions list (systems NOT to scan)
- [ ] Testing window and rate limits agreed
- [ ] Technical and management POCs identified
- [ ] Incident escalation procedure defined

### Technical preparation

- [ ] Client IT notified of scan schedule
- [ ] Firewall/WAF teams alerted
- [ ] Monitoring teams informed (reduce false-positive pages)
- [ ] Credentials for authenticated scans collected (if in scope)
- [ ] Agent deployment planned (if endpoint engines sold)

### Platform readiness

- [ ] `GET /api/health` returns OK
- [ ] Worker processing jobs
- [ ] Database backups current
- [ ] Alerting configured (manual 15)

---

## Step-by-step onboarding

### 1. Log in to Command Center

Navigate to `/command-center/login`.

Authenticate with `POST /api/login`. Complete MFA if enabled.

Verify role is **operator** or higher (required for client create and scans).

### 2. Create client record

Command Center → **Clients** → **Add Client**

Required fields:

| Field | Guidance |
|-------|----------|
| Legal name | Match contract entity |
| Primary domain | Main authorized domain |
| Authorized domains | All in-scope FQDNs and wildcards |
| IP ranges | CIDR notation for network scans |
| Exclusions | Systems explicitly out of scope |
| ROE notes | Rules of Engagement summary |

Backend validates scope before scans target out-of-authorization assets.

Billing gate: `enforce_client_create` checks subscription and `max_clients` plan limit.

### 3. Document Rules of Engagement (ROE)

Store in client notes:

- Permitted scan types and engines
- Time windows (e.g., weekends only)
- Maximum request rate / bandwidth
- Prohibited actions (DoS, social engineering unless authorized)
- Emergency stop contact (24/7 phone)

Align with `/ONBOARDING_RUNBOOK.md` enterprise template.

### 4. Configure scan schedule (optional)

Command Center → **Schedules**

Set cron-like recurrence for recurring assessments. Scheduled runs call `gate_scan_enqueue_n` for batch quota checks.

### 5. Run first authorized scan

Start with low-impact reconnaissance:

1. Open an engine hub (e.g., Domain Discovery, DNS Recon)
2. Select the new client
3. Confirm target is within authorized scope
4. Click **Run**

API path: `POST /api/command-center/scan` with `{ engine, client_id, target }`.

Monitor job at **Jobs** (`/jobs`). Worker must be running.

### 6. Review initial findings

Command Center → **Findings**

Triage by severity. Verify findings map to authorized assets only. False positives from adjacent infrastructure indicate scope misconfiguration — stop and correct.

### 7. Deploy endpoint agent (if in scope)

If contract includes endpoint detection engines (~45 `agent_required` engines):

1. Generate enrollment token in **Agent Management**
2. Install via `GET /install/agent.sh` or `GET /install/agent.ps1`
3. Confirm agent online before running agent-gated engines

See manual **12**.

### 8. Deliver first report

Export PDF/CSV from Findings or Reports module. Include scope statement and ROE reference.

---

## Emergency procedures

### Immediate scan stop

1. Cancel running jobs in **Jobs** dashboard
2. Disable schedules for the client
3. Notify client emergency contact
4. Document incident in audit log notes

### Scope violation discovered

1. **Stop all scans** for affected client immediately
2. Notify client POC and internal legal
3. Review audit logs for unauthorized targets
4. Correct client scope before resuming

### Platform incident during engagement

Follow `/SLA_AND_STATUS.md` escalation. Preserve logs:

```bash
journalctl -u weissman-server --since "1 hour ago" > incident-server.log
journalctl -u weissman-worker --since "1 hour ago" > incident-worker.log
```

---

## Verification

- [ ] Client visible in Clients list with correct authorized domains
- [ ] Test scan completes; findings appear in Findings
- [ ] No findings on excluded assets
- [ ] Agent online (if endpoint scope)
- [ ] PDF report generated and reviewed by lead analyst
- [ ] Customer sign-off on onboarding checklist (manual 18)

---

## Related manuals

- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [11-findings-reports](11-findings-reports.md)
- [12-endpoint-agent](12-endpoint-agent.md)
- `/ONBOARDING_RUNBOOK.md` — extended enterprise runbook
