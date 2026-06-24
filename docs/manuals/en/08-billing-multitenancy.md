# 08 — Billing & Multi-Tenancy

## Purpose

Configure tenant isolation, Paddle subscription billing, scan quotas, and enforcement gates that protect commercial limits in production deployments.

---

## Prerequisites

- PostgreSQL with billing migrations applied
- Paddle Billing account (sandbox for staging, production for live)
- `WEISSMAN_ENV=production` for automatic strict billing default
- Admin role for tenant and billing configuration

---

## Multi-tenancy model

Weissman isolates customer data by **tenant**:

- Row-Level Security (RLS) on app tables via `weissman_app` DB role
- Auth plane uses `weissman_auth` role (BYPASSRLS for login only)
- Each tenant has users, clients, findings, usage counters, and optional Paddle subscription

Tenant slug `default` is the bootstrap workspace. Enterprise deployments may provision additional tenants via admin APIs or signup flow.

---

## Billing architecture

Implementation: `fingerprint_engine/src/billing/mod.rs`

| Component | Role |
|-----------|------|
| `tenant_subscriptions` | Paddle subscription state per tenant |
| `billing_plans` | Plan slugs, max clients, monthly scan quota |
| `tenant_usage_counters` | Rolling monthly scan counts |
| Paddle webhooks | Subscription lifecycle events |
| `gate_scan_enqueue` | Blocks scan job insertion when quota exceeded |

### Strict billing mode

`WEISSMAN_BILLING_STRICT` controls enforcement:

- **`1` / `true`:** Client create + scan enqueue require active/trialing subscription
- **`0` / `false`:** Billing gates skipped (self-hosted unlimited contracts only)

**Defaults:**

1. Explicit `WEISSMAN_BILLING_STRICT` env var wins
2. Else `WEISSMAN_ENV=production` → strict **on**
3. Else if `PADDLE_API_KEY` set → strict **on**
4. Else strict **off** (local dev)

---

## Step-by-step: Paddle setup

### 1. Configure environment variables

```bash
PADDLE_API_KEY=pdl_live_apikey_...
PADDLE_ENVIRONMENT=production
PADDLE_WEBHOOK_SECRET=pdl_ntfset_...
WEISSMAN_BILLING_STRICT=1
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
```

Sandbox testing: `PADDLE_ENVIRONMENT=sandbox` with sandbox API key.

### 2. Register webhook endpoint

Point Paddle to your deployment webhook URL (see `fingerprint_engine/src/billing/webhook.rs` for route).

Verify signature using `PADDLE_WEBHOOK_SECRET`.

### 3. Map plan price IDs

Billing plans in DB reference Paddle price IDs (`pri_*`). Customer-specific catalog must be configured per deployment — see manual **00** sales checklist.

Plans define:

- `max_clients` — enforced at client create (`enforce_client_create`)
- Monthly scan quota — enforced at scan enqueue (`gate_scan_enqueue`, `gate_scan_enqueue_n`)

### 4. Pilot / evaluation override

For enterprise trials without Paddle:

```bash
WEISSMAN_BILLING_STRICT=0
```

Document in signed SOW. Re-enable strict mode before production billing cutover.

---

## Enforcement points

All scan and async job paths call billing gates:

| Action | Gate function |
|--------|---------------|
| Command Center scan | `gate_scan_enqueue` |
| Scheduled scans | `gate_scan_enqueue_n` (batch count) |
| Client creation | `enforce_client_create` |
| Scan run-all | Quota check before bulk enqueue |

When blocked, API returns error message indicating subscription or quota issue. Command Center Billing page shows current usage.

---

## Command Center billing UI

Path: `/command-center/billing` (admin role)

Operators can:

- View current plan and usage counters
- Open Paddle checkout (when configured)
- See subscription status (active, trialing, past_due, canceled)

---

## Self-serve signup (SaaS)

Optional public signup at `deploy/public/signup.html` → `POST /api/auth/signup`.

Requires:

```bash
WEISSMAN_SELF_SERVE_SIGNUP=true
WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION=true
WEISSMAN_SMTP_ENABLED=true
# + SMTP credentials
```

New tenants provision with default plan; Paddle checkout completes subscription.

---

## Verification

```bash
# Check billing strict flag at runtime (admin API or logs)
curl -sf -b cookies.txt https://localhost/api/billing/status

# Attempt scan without subscription (strict on) → expect quota error
curl -X POST -b cookies.txt https://localhost/api/command-center/scan \
  -H 'Content-Type: application/json' \
  -d '{"engine":"dns_recon","client_id":1,"target":"example.com"}'

# With active subscription → job enqueued
docker compose logs worker | grep "claimed job"
```

Confirm webhook delivery in Paddle dashboard after test purchase.

Monitor `tenant_usage_counters` for expected increment after successful scans.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "Subscription not provisioned" | Webhook not received; manually sync or replay webhook |
| Scans blocked unexpectedly | Check monthly quota; upgrade plan or reset counter (admin) |
| Checkout 503 | `PADDLE_API_KEY` missing or wrong environment |
| Strict mode in dev | Set `WEISSMAN_BILLING_STRICT=0` locally |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [00-sales-delivery-readiness](00-sales-delivery-readiness.md)
