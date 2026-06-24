# 19 — Go-Live: Optional Services & Staging

## Purpose

Close the **seven remaining gaps** before full customer handoff: Paddle `pri_*` price IDs, SMTP for self-serve signup, LLM for Council/General Mission, OAST, agent binaries per OS, Docker build on staging, and QA (manual 18). Video/LMS is optional only.

---

## Prerequisites

- Manuals **02** (Docker), **05** (security), **06** (env), **08** (billing)
- Staging host with Docker (8GB+ RAM recommended for builds)
- Strong `WEISSMAN_JWT_SECRET` and `WEISSMAN_ADMIN_PASSWORD` in `.env`

---

## Quick start (staging)

```bash
cp deploy/env.staging.example .env
# Fill secrets, pri_* IDs, LLM URL as needed

docker compose -f docker-compose.yml -f docker-compose.staging.yml \
  --profile staging --profile oast up -d --build

./scripts/staging-qa.sh --live http://localhost
```

Mailpit UI: `http://localhost:8025`

---

## 1. Paddle — `pri_*` price IDs (manual 08)

### In Paddle Dashboard

1. **Catalog → Products** — create/confirm Starter, Professional, Enterprise.
2. For each product: **Prices** — copy `pri_...` (sandbox or live).
3. **Developer tools → Notifications** — webhook to `https://your-domain/api/billing/paddle/webhook`.

### In `.env`

```bash
PADDLE_ENVIRONMENT=sandbox          # or production
PADDLE_API_KEY=pdl_...
PADDLE_WEBHOOK_SECRET=pdl_ntfset_...
WEISSMAN_PADDLE_PRICE_STARTER=pri_...
WEISSMAN_PADDLE_PRICE_PROFESSIONAL=pri_...
WEISSMAN_PADDLE_PRICE_ENTERPRISE=pri_...
WEISSMAN_BILLING_STRICT=1
```

### PostgreSQL (alternative / override)

Use `deploy/go-live/paddle-price-ids.sql.example` — replace `pri_REPLACE_*` and run against Postgres.

**Verify:** Billing → Usage in Command Center; checkout does not return 503.

---

## 2. SMTP — self-serve signup (manual 06)

Self-serve signup sends verification email. On staging use **Mailpit** (`staging` profile).

```bash
WEISSMAN_SELF_SERVE_SIGNUP=1
WEISSMAN_SMTP_ENABLED=true
WEISSMAN_SMTP_HOST=mailpit
WEISSMAN_SMTP_PORT=1025
WEISSMAN_SMTP_FROM=noreply@your-domain.example
WEISSMAN_SMTP_TO=admin@localhost
```

**Production:** real SMTP (SendGrid, SES, Postfix) — same `WEISSMAN_SMTP_*` variables.

**Verify:** new signup → message in Mailpit (8025) or target inbox.

---

## 3. LLM — Council / General Mission (manual 15)

**OpenAI-compatible** endpoint (vLLM, Ollama, Azure OpenAI):

```bash
WEISSMAN_LLM_BASE_URL=http://host.docker.internal:11434/v1
WEISSMAN_LLM_MODEL=llama3.2
# optional: OPENAI_API_KEY=...
```

If LLM runs on the host, use `host.docker.internal` (Linux: add `extra_hosts` in compose if needed).

**Verify:**

```bash
curl -sf "${WEISSMAN_LLM_BASE_URL}/models"
```

Council debate and General Mission return responses, not "LLM unavailable".

---

## 4. OAST — out-of-band (manual 13)

Fuzz/OAST engines use `WEISSMAN_OAST_DOMAIN` + `WEISSMAN_OAST_LISTENER_URL`.

### Staging (`oast` profile)

```bash
WEISSMAN_OAST_DOMAIN=oast.localhost
WEISSMAN_OAST_LISTENER_URL=http://oast:9090
```

```bash
docker compose -f docker-compose.yml -f docker-compose.staging.yml --profile oast up -d oast
```

### Production

- Deploy `weissman-oast-server` on a separate host (`deploy/oast.Dockerfile`).
- Wildcard DNS: `*.oast.your-domain.example` → listener IP.
- Backend/worker: `WEISSMAN_OAST_LISTENER_URL=https://oast.your-domain.example`.

**Verify:** OOB engine scan → hit in `oast_interaction_hits` / status API.

---

## 5. Agent binaries per OS

| Path | When |
|------|------|
| **Docker backend** | `deploy/backend.Dockerfile` — agent at `/srv/bin/agents/linux-{x86_64,aarch64}-gnu/` |
| **Native dev** | `./scripts/package_agent_binaries.sh` → `bin/agents/` |

```bash
curl -sf http://localhost/install/agent.sh | head
```

Linux x64/aarch64 covered in the backend image; Windows/macOS need separate CI/cross-build.

---

## 6. Docker build on staging

```bash
docker compose -f docker-compose.yml -f docker-compose.staging.yml \
  --profile staging --profile oast build --no-cache backend worker oast

docker compose -f docker-compose.yml -f docker-compose.staging.yml \
  --profile staging --profile oast up -d
```

**Pass:** all services healthy; `curl -sf http://localhost/api/health`.

---

## 7. QA — manual 18

```bash
./scripts/staging-qa.sh
./scripts/staging-qa.sh --live http://localhost
```

Full checklist: [18-qa-verification.md](18-qa-verification.md).

---

## 8. Video / LMS (optional)

Not required for go-live. Recommended as a recorded workshop linked from manual **00** or Professional contract.

---

## Summary

| Gap | Config | Manual |
|-----|--------|--------|
| Paddle `pri_*` | `WEISSMAN_PADDLE_PRICE_*`, SQL example | 08 |
| SMTP signup | `WEISSMAN_SMTP_*`, Mailpit | 06 |
| LLM | `WEISSMAN_LLM_BASE_URL` | 15 |
| OAST | profile `oast`, `WEISSMAN_OAST_*` | 13 |
| Agent binaries | Dockerfile + script | 12 |
| Staging build | `docker-compose.staging.yml` | 02 |
| QA | `scripts/staging-qa.sh` | 18 |
| Video/LMS | workshop | — |

---

## Repo helpers

| File | Role |
|------|------|
| `deploy/env.staging.example` | Staging `.env` template |
| `docker-compose.staging.yml` | Mailpit + OAST overlay |
| `deploy/go-live/paddle-price-ids.sql.example` | DB price ID updates |
| `deploy/oast.Dockerfile` | OAST image |
| `scripts/staging-qa.sh` | Automated QA |
