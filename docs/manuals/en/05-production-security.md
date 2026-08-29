# 05 — Production Security Hardening

## Purpose

Configure Weissman for **production-grade security**: startup guards that refuse weak configuration, HTTPS-only sessions, protected metrics, billing enforcement, and human-in-the-loop controls for destructive operations.

---

## Prerequisites

- Deployment method chosen (manual 02, 03, or 04)
- TLS certificate and reverse proxy in place
- Secrets generated with `openssl rand -base64 48` (never reuse dev defaults)
- Security reviewer access to `SECURITY_AND_COMPLIANCE.md` and `SIG_CAIQ_PREP_QA.md`

---

## Core production switch

Set on **both** `weissman-server` and `weissman-worker`:

```bash
WEISSMAN_ENV=production
```

This activates guards in `fingerprint_engine/src/security_startup.rs` (`enforce_production_security_policy`). Without it, the server runs in permissive dev mode even with real secrets.

### What production guards enforce

| Check | Failure mode |
|-------|--------------|
| `WEISSMAN_JWT_SECRET` missing or < 48 chars | Server/worker refuses boot |
| Known weak JWT values (`changeme`, `ci-engine-smoke-secret`, template placeholders) | Refuses boot |
| Weak DB password fragments in URLs | Refuses boot |
| `WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1` | Refuses boot |
| `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1` | Refuses boot |
| `WEISSMAN_COOKIE_SECURE` not enabled (server) | Refuses boot |
| `WEISSMAN_MIGRATE_URL` unset (server) | Refuses boot |
| `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` unset or < 32 chars (server) | Refuses boot |
| `WEISSMAN_METRICS_TOKEN` unset or < 32 chars (server) | Refuses boot |
| `REDIS_URL` unset without `WEISSMAN_ALLOW_SINGLE_NODE=1` (server) | Refuses boot |
| `WEISSMAN_JOB_ORCHESTRATOR_SECRET` unset or < 32 chars (server + worker) | Refuses boot |
| `WEISSMAN_TRUST_PROXY_CIDRS` unset (server) | Refuses boot — dual-control headers would otherwise be injectable via direct `:8000` |
| JWT via `?access_token=` query param | Rejected at runtime |

---

## Step-by-step hardening checklist

### 1. Rotate all secrets

```bash
openssl rand -base64 48   # WEISSMAN_JWT_SECRET (minimum 48 characters enforced at boot)
openssl rand -base64 48   # WEISSMAN_METRICS_TOKEN (≥32)
openssl rand -base64 48   # WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET (≥32)
openssl rand -base64 48   # WEISSMAN_JOB_ORCHESTRATOR_SECRET (≥32)
```

Generate unique Postgres passwords for `weissman_app`, `weissman_auth`, and superuser migration role.

Change default admin password immediately after first login.

### 2. Enable secure session cookies

```bash
WEISSMAN_COOKIE_SECURE=1
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
```

Access JWT lifetime defaults to 15 minutes (`WEISSMAN_ACCESS_TOKEN_MINUTES`). Refresh tokens use HttpOnly cookies (`WEISSMAN_REFRESH_TOKEN_DAYS`, default 30).

Login endpoint: **`POST /api/login`** (not `/api/auth/login`).

### 3. Configure destructive-action confirmation

Destructive paths (auto-heal execute, deception deploy, containment) require:

```bash
WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET=<long-random>
```

Operators must send header:

```
X-Weissman-Destructive-Confirm: <exact secret value>
```

Implemented in `fingerprint_engine/src/security_hardening.rs`. In production, missing secret blocks server start; missing header returns 403 at runtime.

Nginx (or any reverse proxy) **must not** be the only control. Overlay/pod/SSRF clients can speak to Axum on `:8000` and inject the same headers. Middleware `dual_control_proxy_guard` (outermost layer) accepts those headers only when `ConnectInfo` peer IP is in `WEISSMAN_TRUST_PROXY_CIDRS`; every other peer is **403 Forbidden** immediately.

```bash
# Compose/VPS docker networks. On Kubernetes pin to the ingress controller only
# (never the cluster pod CIDR — that re-opens in-cluster SSRF to :8000).
WEISSMAN_TRUST_PROXY_CIDRS=172.16.0.0/12
```

**Required in production** — empty CIDR list refuses server boot.

### 4. Protect metrics and admin surfaces

```bash
WEISSMAN_METRICS_TOKEN=<random>
```

`GET /api/metrics` requires `Authorization: Bearer <token>` in production.

Restrict CEO routes (`/ceo`, `/api/ceo/*`) to `ceo` role or superadmin only.

### 5. Enable billing strict mode

Production default: `WEISSMAN_BILLING_STRICT=1` (auto-on when `WEISSMAN_ENV=production`).

Self-hosted unlimited contracts may set `WEISSMAN_BILLING_STRICT=0` **only with written agreement** — document in customer SOW.

Scan paths call `gate_scan_enqueue` in `fingerprint_engine/src/billing/mod.rs`.

### 6. Network and TLS

- Expose only 443 (and 80 → redirect) publicly
- Postgres and Redis not reachable from the internet
- Set `WEISSMAN_TRUST_PROXY_HEADERS=1` only behind a trusted reverse proxy
- **Required in production:** `WEISSMAN_TRUST_PROXY_CIDRS` — dual-control headers are accepted only from those TCP peers (403 otherwise)

Never set `WEISSMAN_ALLOW_INSECURE_TLS=1` in production.

### 7. Redis for distributed controls

```bash
REDIS_URL=redis://redis-host:6379/0
```

Required for multi-replica rate limits, login lockout (`/api/login`, `/api/auth/mfa/verify`), and agent fleet registry. When Redis is configured in production, middleware **fail-closed** (503) if Redis is unreachable — no silent in-memory fallback.

Zero-trust job bus (requires `REDIS_URL` + dedicated orchestrator secret):

```bash
WEISSMAN_JOB_ORCHESTRATOR_SECRET=<openssl rand -base64 48>
```

See `docs/operations/AUTH-DB-ROTATION.md` for zero-downtime `weissman_auth` password rotation.

### 8. SAML / OIDC (if enabled)

- Set `WEISSMAN_XMLSEC1_BINARY` for SAML assertion verification
- Never enable `WEISSMAN_SAML_INSECURE_SKIP_VERIFY` in production
- Match IdP redirect URIs to `WEISSMAN_PUBLIC_BASE_URL`

See manual **14**.

### 9. Self-serve signup (SaaS only)

Only enable when intentionally operating a public signup funnel:

```bash
WEISSMAN_SELF_SERVE_SIGNUP=true
WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION=true
```

Requires SMTP configuration. Never set `WEISSMAN_SIGNUP_RETURN_LINK=1` in production.

### 10. IaC Live AWS (runtime feature flag)

The IaC Misconfig engine supports live AWS/K8s reconciliation when compiled with the `live-aws` feature (workspace default).

**Runtime kill-switch (recommended in staging before go-live):**

```bash
# 0 = graph-only — no live AWS IAM/S3/API calls
WEISSMAN_IAC_LIVE_AWS=0
```

When `WEISSMAN_IAC_LIVE_AWS=0`, scans remain graph-only even if params include `live_blast` or `aws_cross_account_role_arn`.

**Full live mode (authorized production):**

```bash
WEISSMAN_IAC_LIVE_AWS=1   # or unset — enabled by default when feature is compiled
```

Also requires cross-account role ARN, `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` for cloud deploy paths, and operator RBAC.

---

## Security headers and static legal pages

Gateway/nginx configs include `deploy/nginx-security-headers.inc`. Legal pages ship from `deploy/public/` (terms, privacy, DPA, subprocessors, security policy).

---

## Verification

```bash
# Should refuse weak config — test on staging only
WEISSMAN_ENV=production WEISSMAN_JWT_SECRET=changeme ./target/release/weissman-server
# Expect: startup error

curl -sf https://your-domain.example/api/health
curl -s -o /dev/null -w "%{http_code}" https://your-domain.example/api/metrics
# Expect: 401 without Bearer token

# Login lockout after failed attempts (requires Redis)
# Destructive action without header → 403
```

Review audit logs in Command Center after test destructive action attempt.

Cross-reference procurement pack: `/SECURITY_AND_COMPLIANCE.md`.

---

## Related manuals

- [06-environment-configuration](06-environment-configuration.md) — full env reference
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md) — roles and MFA
- [08-billing-multitenancy](08-billing-multitenancy.md) — quota gates
- [14-sso-identity](14-sso-identity.md) — IdP integration
- [16-operations-monitoring](16-operations-monitoring.md) — metrics and alerting
- [18-qa-verification](18-qa-verification.md) — acceptance tests
