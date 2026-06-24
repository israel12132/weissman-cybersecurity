# 17 — Troubleshooting

## Purpose

Diagnose and resolve common Weissman platform failures across installation, authentication, scans, billing, agents, and integrations.

---

## Prerequisites

- Shell access to deployment host or kubectl
- Logs access (Docker, journalctl, or K8s)
- Operator credentials for API smoke tests
- This manual pack + `/docs/operations.md`

---

## Diagnostic quick reference

| Symptom | First check |
|---------|-------------|
| 502 Bad Gateway | Backend health; PORT mismatch |
| Login fails | `POST /api/login`; Redis lockout |
| Scans stuck queued | Worker running |
| 403 on scans | Billing quota / RBAC role |
| Agent offline | Token, firewall, WSS path |
| SSO broken | `WEISSMAN_PUBLIC_BASE_URL`, IdP config |
| Server won't start | `security_startup.rs` error in logs |

---

## Installation and startup

### Backend exits immediately on start

**Cause:** Production security guards (`fingerprint_engine/src/security_startup.rs`).

```bash
docker compose logs backend --tail 50
# or
journalctl -u weissman-server -n 50
```

Common messages:

| Error | Fix |
|-------|-----|
| `WEISSMAN_JWT_SECRET must be at least 32 characters` | Generate strong secret |
| `matches a known weak/default value` | Replace template placeholder |
| `WEISSMAN_COOKIE_SECURE must be 1` | Set cookie secure + HTTPS |
| `WEISSMAN_MIGRATE_URL` required | Set migration superuser URL |
| `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` unset | Generate and set secret |
| Weak DB password fragment | Rotate Postgres passwords |

Ensure `WEISSMAN_ENV=production` only when fully hardened.

### Docker Compose exit code 15

**Cause:** Invalid `.env` syntax — often unquoted values containing `:`.

Fix: quote affected variables. Minimum required:

```bash
WEISSMAN_JWT_SECRET=...
WEISSMAN_ADMIN_PASSWORD=...
```

### 502 on /api or /command-center

**Cause:** Backend not listening or wrong upstream port.

```bash
deploy/fix-weissman-502.sh
curl -sf http://127.0.0.1:8000/api/health
grep PORT /etc/weissman/weissman.env
```

Verify nginx upstream matches `PORT` (default 8000).

---

## Authentication

### Cannot log in (401)

1. Confirm endpoint: **`POST /api/login`** (not `/api/auth/login`)
2. Verify `WEISSMAN_ADMIN_EMAIL` / password
3. Check account lockout — Redis required for distributed lockout
4. If MFA enabled, complete `/api/auth/mfa/verify`

```bash
redis-cli GET "weissman:lockout:*"
```

### Session expires quickly

Access token default 15 min. Increase `WEISSMAN_ACCESS_TOKEN_MINUTES` (max 240) if policy allows.

### 403 "role required"

User needs higher role. Check `GET /api/auth/me` → `role`. Hierarchy: viewer < analyst < operator < admin < ceo.

---

## Scans and jobs

### Jobs remain queued

**Cause:** Worker not running.

```bash
docker compose ps worker
systemctl status weissman-worker
docker compose logs worker --tail 30
```

Fix: start worker. Verify `DATABASE_URL` identical to server.

### Scan returns billing error

**Cause:** `gate_scan_enqueue` blocked.

- Check `WEISSMAN_BILLING_STRICT`
- Verify Paddle subscription active
- Check monthly quota on Billing page

Pilot override: `WEISSMAN_BILLING_STRICT=0` (contract only).

### Scan returns scope error

Target not in client authorized domains. Update client scope in Command Center.

### Engine shows no findings (real_probe)

Review worker logs for probe errors. Check network egress from worker container to target.

### Agent engine empty state

Expected until agent online. Not a bug — install agent (manual 12).

---

## Endpoint agent

### Install script 404

Run `bash scripts/package_agent_binaries.sh`. Verify routes:

- `GET /install/agent.sh`
- `GET /install/agent.ps1`

### SHA256 mismatch

Rebuild agent; republish binaries to `/install/binaries/`.

### Agent shows offline

- Verify outbound HTTPS to `WEISSMAN_PUBLIC_BASE_URL`
- Check WebSocket path through proxy (upgrade headers)
- Regenerate token if revoked

---

## SSO

### Redirect URI mismatch

IdP callback must match `WEISSMAN_PUBLIC_BASE_URL` exactly (scheme + host).

### SAML signature verification fails

Install `xmlsec1`; set `WEISSMAN_XMLSEC1_BINARY`. Never use `WEISSMAN_SAML_INSECURE_SKIP_VERIFY` in production.

---

## Integrations and webhooks

### CI webhook not firing

Verify URL, HMAC secret, and `client_id`. Check gateway routes for `/hooks/cicd/*`.

### Alert webhook silent

Test `WEISSMAN_ALERT_WEBHOOK_URL` with curl. Review alert rule conditions and cooldown.

---

## Database and Redis

### Connection pool exhausted

Raise `WEISSMAN_APP_POOL_MAX`. Check for connection leaks in logs.

### Migration failures

```bash
docker compose logs backend | grep -i migrat
```

Run migrations manually with `WEISSMAN_MIGRATE_URL` credentials if needed.

### Redis unavailable

Rate limits and lockout degrade. Restore Redis or remove dependency for single-node pilot only.

---

## Destructive actions

### 403 on auto-heal / deception

Send header:

```
X-Weissman-Destructive-Confirm: <WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET>
```

Secret must match env var exactly.

---

## Verification after fix

```bash
curl -sf https://your-domain.example/api/health
# Login + one smoke scan
# Worker claims job within 60s
```

Run manual **18** subset for regression confidence.

---

## Escalation

1. Collect logs (server + worker, last 1 hour)
2. Note exact error message and timestamp
3. Reference `/SLA_AND_STATUS.md` for support tiers
4. Preserve `audit_logs` for security incidents

---

## Related manuals

- [02-installation-docker](02-installation-docker.md)
- [05-production-security](05-production-security.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [12-endpoint-agent](12-endpoint-agent.md)
- [16-operations-monitoring](16-operations-monitoring.md)
- [18-qa-verification](18-qa-verification.md)
