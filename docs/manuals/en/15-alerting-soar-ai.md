# 15 — Alerting, SOAR & AI

## Purpose

Configure alert rules, SOAR playbooks, on-call notifications, and AI-assisted modules (Supreme Council, General Mission) for proactive security operations.

---

## Prerequisites

- Operator role for alert/playbook configuration
- Admin role for AI model settings
- Optional: `WEISSMAN_ALERT_WEBHOOK_URL`, `WEISSMAN_PAGER_WEBHOOK_URL`
- Optional: OpenAI-compatible LLM endpoint (`WEISSMAN_LLM_BASE_URL`, `OPENAI_API_KEY`)
- Redis for alert rate limiting

---

## Alerting architecture

```
Finding / PoE / Job event
    → Alert rule evaluation
    → Actions: webhook, email, page_oncall, SOAR playbook
    → Audit log + notification delivery
```

Environment variables:

| Variable | Purpose |
|----------|---------|
| `WEISSMAN_ALERT_WEBHOOK_URL` | Generic JSON webhook (Slack, Teams) |
| `WEISSMAN_PAGER_WEBHOOK_URL` | PagerDuty / Opsgenie |
| `WEISSMAN_SMTP_ENABLED` + `WEISSMAN_SMTP_*` | Email alerts |

---

## Step-by-step: alert rules

### 1. Open Alerting dashboard

Command Center → **Alerting** (or Security Operations hub)

### 2. Create rule

Example conditions:

- Severity = Critical
- KEV badge present
- Engine in `{rce_*, deser_*}` set
- Client = specific engagement

### 3. Configure actions

| Action | Use case |
|--------|----------|
| `webhook` | Slack channel notification |
| `email` | Client POC + internal distro |
| `page_oncall` | 24/7 SOC escalation |
| `soar_playbook` | Automated response chain |

### 4. Test rule (staging)

Inject test finding or use rule test button. Confirm webhook delivery and no duplicate spam (cooldown windows).

### 5. Production enable

Document rules in customer runbook. Align with client monitoring to avoid alert fatigue.

---

## SOAR playbooks

Implementation: `fingerprint_engine/src/soar_playbook.rs`

Playbooks chain actions:

- Create ticket (Jira/ServiceNow via webhook)
- Enrich finding with threat intel
- Notify channel
- Optional containment step (requires destructive confirm header)

### Build a playbook

Command Center → **Playbook Builder** → New Playbook

1. Define trigger (alert rule match, manual, schedule)
2. Add steps with conditions
3. Set failure handling (continue vs abort)
4. Publish playbook
5. Link from alert rule

Destructive playbook steps (`containment_execute`, `deception_deploy`) require:

```
X-Weissman-Destructive-Confirm: <WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET>
```

See manual **05**.

---

## Supreme Council (AI debate)

CEO/operator feature for multi-agent LLM debate on complex findings.

Paths:

- `/api/ceo/council/*`
- Council queue in Command Center
- Async job type `council_debate`

Configure models:

```bash
WEISSMAN_LLM_BASE_URL=https://your-llm-host/v1
OPENAI_API_KEY=sk-...
WEISSMAN_COUNCIL_MODEL_*=gpt-4o-mini   # per-role overrides
```

Council uses RAG over findings and intel when embeddings configured:

```bash
WEISSMAN_EMBEDDINGS_MODEL=text-embedding-3-small
```

Without LLM endpoint, Council queues jobs but cannot complete synthesis — document as optional module (manual 00).

Stream events: `/api/ceo/council/sessions/{uuid}/stream` (SSE).

---

## General Mission (CEO control)

CEO Mission Control (`/command-center/ceo`) orchestrates strategic tasks:

- Genesis strategy parameters
- War room streams
- Integrated command deck

Restricted to **`ceo` role** or superadmin (manual 07).

Optional LLM for mission planning via same `WEISSMAN_LLM_BASE_URL`.

---

## Predictive and NL query

| Feature | Env vars |
|---------|----------|
| Ask Weissman (NL query) | `WEISSMAN_NL_QUERY_MODEL` |
| Predictive risk | LLM + historical findings |
| Sovereign self-scan | `WEISSMAN_SOVEREIGN_SELF_SCAN_INTERVAL_SECS` (min 300) |

Read-only DB role for NL query:

```bash
WEISSMAN_READ_ONLY_DATABASE_URL=postgres://weissman_ro:...@host/weissman
```

Without read-only URL, `/api/ask` returns 503.

---

## Verification

```bash
# Alert webhook smoke (staging)
curl -X POST "$WEISSMAN_ALERT_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{"test":true,"source":"weissman-qa"}'

# LLM connectivity
curl -sf "${WEISSMAN_LLM_BASE_URL}/models" \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Council job (ceo cookie)
# POST council debate; poll job status
```

Checklist:

- [ ] Alert rule fires on test Critical finding
- [ ] Webhook received in Slack/PagerDuty
- [ ] Playbook executes non-destructive steps
- [ ] Council job completes when LLM configured
- [ ] CEO routes blocked for non-CEO roles

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Alerts silent | Check rule conditions; verify webhook URL |
| Alert storm | Add cooldown; tighten severity threshold |
| Playbook stuck | Review step logs; check external API creds |
| Council 503 | LLM URL/key missing |
| Destructive step 403 | Missing `X-Weissman-Destructive-Confirm` |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [11-findings-reports](11-findings-reports.md)
- [13-integrations-cicd](13-integrations-cicd.md)
- [16-operations-monitoring](16-operations-monitoring.md)
