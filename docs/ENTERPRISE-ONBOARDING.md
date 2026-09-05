# Weissman Cybersecurity — Enterprise Client Onboarding Guide

**Version:** 1.0 | **Updated:** 2026-08-18  
**Audience:** Customer Success Manager (CSM), Solutions Engineer, IT contacts at the client.

---

## Overview

This guide covers the complete onboarding process for a new Enterprise customer. The process takes **1–5 business days** depending on infrastructure readiness at the client side.

---

## Step 1 — Pre-Signature Checklist (Sales / Legal)

Before signing the contract, confirm the following are agreed:

| Item | Owner | Status |
|------|-------|--------|
| MSA / Order Form signed | Legal (both sides) | ☐ |
| Data Processing Agreement (DPA) signed | Legal | ☐ |
| Deployment model chosen: SaaS IL / SaaS EU / Self-hosted | CTO + Client | ☐ |
| SLA tier selected (Standard 99.95% / Enterprise 99.99%) | Sales | ☐ |
| Region confirmed (`IL` / `EU-West` / `US-East`) | Compliance | ☐ |
| Sub-processors list acknowledged | Client DPO | ☐ |
| Emergency contact (on-call phone) exchanged | CSM | ☐ |
| Security questionnaire (SIG/CAIQ) completed | Weissman CISO | ☐ |

---

## Step 2 — Tenant Provisioning (Weissman Ops)

**Time: ~30 minutes**

```bash
# 1. Create the tenant in the platform database
curl -X POST https://<host>/api/admin/tenants \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<Client Legal Name>",
    "slug": "<client-slug>",
    "region": "IL",
    "plan": "enterprise",
    "mfa_required": true,
    "sso_required": false
  }'

# 2. Create the first admin user for the tenant
curl -X POST https://<host>/api/admin/tenants/<tenant_id>/users \
  -H "Authorization: ******" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "<client-admin@example.com>",
    "role": "admin",
    "send_welcome_email": true
  }'

# 3. Verify tenant isolation (RLS contract)
cargo test --workspace --test rls_contract -- --test-threads=1
```

**Checklist:**
- [ ] Tenant created with correct `region` code
- [ ] `mfa_required = true` for financial-sector clients
- [ ] Admin user received welcome email
- [ ] Tenant appears in `/api/admin/tenants` list

---

## Step 3 — SSO / SAML Integration (Optional, Recommended)

**Time: 1–2 business days (depends on client IdP)**

### Option A — OIDC (Okta, Azure AD, Google Workspace)
```bash
# Set per tenant:
WEISSMAN_OIDC_CLIENT_ID=<value>
WEISSMAN_OIDC_CLIENT_SECRET=<value>
WEISSMAN_OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant>
```

### Option B — SAML 2.0 (any enterprise IdP)
```bash
WEISSMAN_SAML_METADATA_URL=<IdP metadata URL>
WEISSMAN_SAML_ENTITY_ID=https://<host>/saml/metadata
```

**Checklist:**
- [ ] IdP metadata / client credentials received from client
- [ ] SSO tested end-to-end (login → redirect → JIT provisioning)
- [ ] Fallback local login disabled if SSO-only policy required

---

## Step 4 — Alert Delivery Configuration

**Time: 30 minutes**

Configure live alert delivery (required for go-live gate):

```bash
# PagerDuty
printf '%s' '<32-char-routing-key>' > monitoring/secrets/pagerduty_routing_key

# Slack (optional)
printf '%s' 'https://hooks.slack.com/services/...' > monitoring/secrets/slack_api_url

# Dead-man's-switch heartbeat (healthchecks.io or similar)
printf '%s' 'https://hc-ping.com/<uuid>' > monitoring/secrets/watchdog_url

# Restart alertmanager to reload secrets
docker compose restart alertmanager
```

**Verify:**
```bash
./scripts/go_live_check.sh
# All alert-delivery gates must be PASS
```

---

## Step 5 — Network & Scope Configuration

**Time: 1 business day**

```bash
# Define the client's asset inventory in their tenant
curl -X POST https://<host>/api/tenants/<id>/assets \
  -H "Authorization: ******" \
  -d '{ "cidrs": ["10.0.0.0/8", "192.168.1.0/24"], "domains": ["example.com"] }'

# Set scan schedule (cron expression)
curl -X PATCH https://<host>/api/tenants/<id>/config \
  -d '{ "scan_interval_secs": 86400, "scan_cron": "0 2 * * 0" }'
```

**Checklist:**
- [ ] Asset inventory defined (IPs, CIDRs, domains)
- [ ] Scan schedule set to off-peak hours (Sunday 02:00 Israel time recommended)
- [ ] Scope validation confirmed (no out-of-scope scanning)
- [ ] First scan completed successfully

---

## Step 6 — Compliance Configuration

**Time: 2–4 hours**

For Israeli financial-sector clients (banks, insurance, financial services):

```bash
# Verify region is set correctly
grep WEISSMAN_REGION .env  # must be: WEISSMAN_REGION=IL

# Run compliance evidence pack
bash scripts/generate_audit_evidence_pack.sh

# Run Bank of Israel Directive 361 readiness gate
bash scripts/go_live_check.sh
```

**Deliver to client:**
- [ ] `docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md` — mapping to directive
- [ ] `scripts/generate_audit_evidence_pack.sh` output (JSON + PDF)
- [ ] `SIG_CAIQ_PREP_QA.md` — completed security questionnaire
- [ ] `deploy/public/dpa.html` — Data Processing Agreement
- [ ] `SLA_AND_STATUS.md` — SLA terms (99.95% / SEV-1 ≤ 15 min)

---

## Step 7 — Go-Live Validation

```bash
# Full audit gate (G1–G7) — must exit 0
bash scripts/full_audit_gate.sh

# Go-live check — must exit 0 with 0 FAILs
bash scripts/go_live_check.sh

# Optional: live stack check
bash scripts/go_live_check.sh --live https://<production-host>
```

**Checklist:**
- [ ] `full_audit_gate.sh` exits 0
- [ ] `go_live_check.sh` exits 0 (0 FAILs)
- [ ] First scan results visible in Command Center
- [ ] Client admin can log in and see their findings
- [ ] Alerting tested end-to-end (fire test alert → PagerDuty/Slack confirmed)
- [ ] Backup restore drill completed (`scripts/backup_restore_verify.sh`)

---

## Step 8 — Week 1 Handover

See `docs/sales/WEEK-1-GOLIVE-he.md` for the full Week 1 checklist (Hebrew).

**Key items:**
- [ ] CSM intro call with client team
- [ ] Platform walkthrough (Command Center demo)
- [ ] Escalation contacts shared both ways (SLA §7)
- [ ] Maintenance window confirmed (Sunday 02:00–04:00 Israel time)
- [ ] First monthly SLA report scheduled

---

## Scaling to Multiple Clients

The platform is multi-tenant by construction:

| Dimension | Capacity | Notes |
|---|---|---|
| Tenants | Unlimited | Each tenant is RLS-isolated |
| Concurrent scans | Configurable via worker HPA | `deploy/k8s/worker-hpa.yaml` |
| Engines per scan | 573 production engines | 313 real_probe + 212 alias + 48 agent |
| Users per tenant | Unlimited | 5 RBAC roles |
| Regions | IL, EU-West, US-East, AU-East | Per-tenant |

**To add a new client:** repeat Steps 2–7. No infrastructure changes required unless scaling worker replicas.

```bash
# Scale workers for high load (K8s)
kubectl scale deployment weissman-worker --replicas=<n> -n weissman

# Or via HPA tuning:
# deploy/k8s/worker-hpa.yaml — adjust maxReplicas
```

---

## Support Contacts

| Role | Contact |
|---|---|
| Customer Success | csm@weissman.io |
| Technical Support | support@weissman.io |
| Security Incidents | security@weissman.io |
| Emergency (SEV-1) | On-call phone in Order Form |

---

*For go-live verification: `bash scripts/go_live_check.sh`. For compliance evidence: `bash scripts/generate_audit_evidence_pack.sh`.*
