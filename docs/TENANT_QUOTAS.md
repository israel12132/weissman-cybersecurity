# Per-Tenant Resource Quotas

Longer-horizon, plan-based consumption limits — the budget that complements the
short-horizon rate limiters (`http::api_rate_limit` per-IP, `http::tenant_scan_limit`
per-minute). Backed by `weissman_tenant_quota_usage` under **forced RLS**, so one tenant can
never read or spend another's budget. Code: `fingerprint_engine/src/tenant_quota.rs`.

## Model

- **Resource** — what's metered (e.g. `scans`).
- **Window** — `daily` (`YYYY-MM-DD`) or `monthly` (`YYYY-MM`), UTC period buckets.
- **Limit** — the ceiling for the period; `0` = unlimited. The request that takes usage to
  exactly the limit is allowed; the next is denied.
- Accounting is a single atomic upsert-increment inside a tenant transaction, so concurrent
  requests can't lose a count.

Limit resolution: per-tenant override in `system_configs` (key `<resource>_<window>_quota`,
e.g. `scans_monthly_quota`), falling back to the process default env, else `0` (unlimited).

## Enabling (monthly scan quota)

Opt-in — default off, so behaviour is unchanged until an operator turns it on:

```bash
WEISSMAN_SCAN_QUOTA_ENABLED=1
WEISSMAN_DEFAULT_MONTHLY_SCAN_QUOTA=1000   # 0 = unlimited
```

Per-tenant override (beats the env default):

```sql
INSERT INTO system_configs (tenant_id, key, value, description)
VALUES (:tenant, 'scans_monthly_quota', '5000', 'Plan quota')
ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value;
```

## Enforcement

`http::tenant_scan_limit` checks the quota on every scan-trigger POST **before** the
per-minute limiter. Over-quota returns **429** with `Retry-After` and:

```json
{ "code": "quota_exceeded", "resource": "scans", "window": "monthly",
  "used": 1001, "limit": 1000, "remaining": 0, "reset_at_unix": 1780272000 }
```

A quota-store error **fails open** (logged, request allowed) — a transient DB blip must
never block a legitimate scan.

## Observing

- `GET /api/quota` (auth) → `{ ok, quotas: [{ resource, window, used, limit, remaining,
  period_key, reset_at_unix, allowed }] }`. Read-only: it reports usage without consuming.
- Metrics: `weissman_tenant_quota_used{resource}` (gauge),
  `weissman_tenant_quota_denied_total{resource}` (counter).

## Runbook

- **Tenant reports scans rejected with `quota_exceeded`** → they've spent the period budget.
  Check `GET /api/quota`; raise `scans_monthly_quota` for that tenant, or wait for
  `reset_at_unix` (start of next UTC month).
- **`weissman_tenant_quota_denied_total` rising sharply** → either a tenant is over plan, or a
  limit was set too low after a plan change. The per-tenant override takes effect immediately;
  no restart needed.
- **Quota not being enforced** → confirm `WEISSMAN_SCAN_QUOTA_ENABLED=1`. With it unset the
  ledger still records nothing and every scan passes (by design).
- **`quota check failed; allowing` in logs** → the quota store was unreachable; requests are
  passing through (fail-open). Investigate DB health; no data is lost, accounting simply skips
  those requests.

## Testing

- Unit: period-key/reset math (incl. year rollover), allow/deny boundary, unlimited, remaining.
- Integration (`tests/tenant_quota_integration.rs`, live DB under RLS): atomic monotonic
  increment, allow→deny flip at the limit. Runs in CI via `cargo test --all-targets`.
