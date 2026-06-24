# 13 — Integrations & CI/CD

## Purpose

Connect Weissman to external systems: CI/CD pipelines, webhooks, threat intel feeds, and Out-of-Band Application Security Testing (OAST) for blind vulnerability confirmation.

---

## Prerequisites

- Operator role for integration configuration
- Client with authorized scope (manual 09)
- Optional: OAST server deployed (`weissman-oast-server`)
- Network egress from CI runners to platform HTTPS

---

## CI/CD integration

Weissman exposes **unauthenticated webhook endpoints** for pipeline-triggered scans. Secure via secret tokens in pipeline config, IP allowlists, and scope validation.

### Webhook endpoints

| Path | Platform |
|------|----------|
| `/hooks/cicd/github` | GitHub Actions |
| `/hooks/cicd/gitlab` | GitLab CI |
| `/hooks/cicd/bitbucket` | Bitbucket Pipelines |
| `/hooks/cicd/scan` | Generic scan trigger |

Configure in Command Center → **Integrations** → CI/CD.

### Step-by-step: GitHub Actions

1. Create integration in UI; copy webhook URL and signing secret
2. Add repository secret `WEISSMAN_WEBHOOK_SECRET`
3. Add workflow step:

```yaml
- name: Weissman security scan
  run: |
    curl -X POST https://your-domain.example/hooks/cicd/github \
      -H "Content-Type: application/json" \
      -H "X-Hub-Signature-256: sha256=$(echo -n '{}' | openssl dgst -sha256 -hmac ${{ secrets.WEISSMAN_WEBHOOK_SECRET }} | cut -d' ' -f2)" \
      -d '{"repository":"org/repo","ref":"main","client_id":1}'
```

4. Scan job enqueues; findings appear linked to client
5. Optional: fail pipeline on Critical findings via status check API

### Generic scan trigger

`POST /hooks/cicd/scan` accepts JSON with `client_id`, `engine`, `target`. Validates client scope before enqueue.

Billing: CI-triggered scans pass through `gate_scan_enqueue` like manual scans.

---

## Outbound webhooks

Configure platform → external notifications:

```bash
WEISSMAN_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Fires on critical PoE alerts, SOAR fallback paths, and configurable alert rules (manual 15).

Payload includes finding summary, client, severity, and timestamp JSON.

---

## Threat intel feeds

Background intel workers ingest:

- CISA KEV catalog
- FIRST EPSS scores
- Custom IOC feeds (when configured)

Control via environment:

```bash
WEISSMAN_INTEL_KEV_ENABLED=true
WEISSMAN_INTEL_EPSS_ENABLED=true
WEISSMAN_INTEL_DATABASE_URL=postgres://...   # optional separate DB
```

Intel enriches findings automatically (manual 11). Air-gapped deployments may mirror feeds locally.

---

## OAST (Out-of-Band)

Blind SSRF, XXE, and deserialization bugs require callback verification.

Deploy optional OAST server and configure:

```bash
WEISSMAN_OAST_BASE_URL=https://oast.your-domain.example
```

Engines generating OAST tokens register interactions; findings upgrade when callback received.

Separate binary/process — not included in default Docker Compose stack.

---

## Third-party SIEM / ticketing

Export paths:

- **CSV** from Findings (manual 11)
- **Webhook** on alert rule match
- **SOAR playbooks** (manual 15) with Jira/ServiceNow actions

Structured logs with `WEISSMAN_LOG_FORMAT=json` feed centralized logging.

---

## API integrations

Authenticated operators use standard API with session cookie or Bearer token:

```bash
# Trigger scan from automation (operator credentials)
curl -X POST -b cookies.txt https://localhost/api/command-center/scan \
  -H 'Content-Type: application/json' \
  -d '{"engine":"sast_github","client_id":1,"target":"org/repo"}'
```

Rate limits apply (Redis-backedbased). Use service account with `operator` role.

---

## Verification

```bash
# Webhook endpoint reachable
curl -s -o /dev/null -w "%{http_code}" -X POST https://localhost/hooks/cicd/scan \
  -H 'Content-Type: application/json' -d '{}'
# Expect: 401/403 without valid payload (not 404)

# CI smoke: trigger from test pipeline; confirm job in /jobs

# Alert webhook test (staging)
# Trigger critical finding; confirm Slack message
```

Checklist:

- [ ] GitHub/GitLab webhook delivers 200 and enqueues job
- [ ] Findings scoped to correct client
- [ ] Alert webhook fires on test rule
- [ ] OAST callback received (if OAST deployed)

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Webhook 404 | Gateway route missing; check nginx config |
| Signature mismatch | Verify HMAC secret matches UI |
| Scan not enqueued | Billing quota; client_id invalid |
| OAST no callback | DNS/firewall; verify OAST server health |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [11-findings-reports](11-findings-reports.md)
- [15-alerting-soar-ai](15-alerting-soar-ai.md)
- [06-environment-configuration](06-environment-configuration.md)
