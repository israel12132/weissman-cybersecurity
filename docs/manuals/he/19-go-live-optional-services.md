# 19 — Go-Live: שירותים אופציונליים ו-Staging

## מטרה

סגירת **שבעת הפערים** שנותרו לפני handoff מלא: Paddle `pri_*`, SMTP ל-self-serve signup, LLM ל-Council/General Mission, OAST, בינארי Agent, Docker build על staging, ו-QA (ספר 18). וידאו/LMS — אופציונלי בלבד.

---

## דרישות מקדימות

- ספר **02** (Docker), **05** (אבטחה), **06** (env), **08** (billing)
- מכונה staging עם Docker (מומלץ 8GB+ RAM ל-build)
- `.env` עם `WEISSMAN_JWT_SECRET` ו-`WEISSMAN_ADMIN_PASSWORD` חזקים

---

## התחלה מהירה (staging)

```bash
cp deploy/env.staging.example .env
# מלאו סודות, pri_*, LLM URL לפי הצורך

docker compose -f docker-compose.yml -f docker-compose.staging.yml \
  --profile staging --profile oast up -d --build

./scripts/staging-qa.sh --live http://localhost
```

Mailpit UI: `http://localhost:8025`

---

## 1. Paddle — מזהי מחיר `pri_*` (ספר 08)

### ב-Paddle Dashboard

1. **Catalog → Products** — צרו/אשרו Starter, Professional, Enterprise.
2. לכל product: **Prices** → העתיקו `pri_...` (sandbox או live).
3. **Developer tools → Notifications** — webhook ל-`https://your-domain/api/billing/paddle/webhook`.

### ב-`.env`

```bash
PADDLE_ENVIRONMENT=sandbox          # או production
PADDLE_API_KEY=pdl_...
PADDLE_WEBHOOK_SECRET=pdl_ntfset_...
WEISSMAN_PADDLE_PRICE_STARTER=pri_...
WEISSMAN_PADDLE_PRICE_PROFESSIONAL=pri_...
WEISSMAN_PADDLE_PRICE_ENTERPRISE=pri_...
WEISSMAN_BILLING_STRICT=1
```

### ב-PostgreSQL (חלופה / override)

```bash
# deploy/go-live/paddle-price-ids.sql.example — החליפו pri_REPLACE_* והריצו:
docker compose exec postgres psql -U postgres -d weissman \
  -c "UPDATE billing_plans SET paddle_price_id = 'pri_...' WHERE slug = 'starter';"
```

**אימות:** Billing → Usage ב-Command Center; checkout לא מחזיר 503.

---

## 2. SMTP — self-serve signup (ספר 06)

Self-serve signup שולח אימייל אימות. ב-staging — **Mailpit** (profile `staging`).

```bash
WEISSMAN_SELF_SERVE_SIGNUP=1
WEISSMAN_SMTP_ENABLED=true
WEISSMAN_SMTP_HOST=mailpit
WEISSMAN_SMTP_PORT=1025
WEISSMAN_SMTP_FROM=noreply@your-domain.example
WEISSMAN_SMTP_TO=admin@localhost
```

**Production:** SMTP אמיתי (SendGrid, SES, Postfix) — אותם משתני `WEISSMAN_SMTP_*`.

**אימות:** הרשמה חדשה → מייל ב-Mailpit (8025) או בתיבת היעד.

---

## 3. LLM — Council / General Mission (ספר 15)

Endpoint **OpenAI-compatible** (vLLM, Ollama, Azure OpenAI):

```bash
WEISSMAN_LLM_BASE_URL=http://host.docker.internal:11434/v1
WEISSMAN_LLM_MODEL=llama3.2
# אופציונלי: OPENAI_API_KEY=...
```

אם ה-LLM על ה-host ולא ב-Docker — `host.docker.internal` (Linux: הוסיפו `extra_hosts` ב-compose).

**אימות:**

```bash
curl -sf "${WEISSMAN_LLM_BASE_URL}/models"
```

Council debate / General Mission מחזירים תשובה ולא "LLM unavailable".

---

## 4. OAST — out-of-band (ספר 13)

מנועי fuzz/OAST משתמשים ב-`WEISSMAN_OAST_DOMAIN` + `WEISSMAN_OAST_LISTENER_URL`.

### Staging (profile `oast`)

```bash
WEISSMAN_OAST_DOMAIN=oast.localhost
WEISSMAN_OAST_LISTENER_URL=http://oast:9090
# WEISSMAN_OAST_API_KEY=  # אופציונלי
```

```bash
docker compose -f docker-compose.yml -f docker-compose.staging.yml --profile oast up -d oast
```

### Production

- פריסת `weissman-oast-server` על host נפרד (`deploy/oast.Dockerfile`).
- DNS wildcard: `*.oast.your-domain.example` → IP ה-listener.
- Backend/worker: `WEISSMAN_OAST_LISTENER_URL=https://oast.your-domain.example`.

**אימות:** סריקת מנוע OOB → hit ב-`oast_interaction_hits` / status API.

---

## 5. בינארי Agent לפי OS

| מסלול | מתי |
|--------|-----|
| **Docker backend** | `deploy/backend.Dockerfile` — `weissman-agent` ב-`/srv/bin/agents/linux-{x86_64,aarch64}-gnu/` |
| **Native dev** | `./scripts/package_agent_binaries.sh` → `bin/agents/` |

```bash
curl -sf http://localhost/install/agent.sh | head
curl -sf http://localhost/api/agents/download/linux-x86_64-gnu -o /dev/null
```

Windows/macOS — cross-compile או CI נפרד; Linux מכוסה ב-image.

---

## 6. Docker build על staging

```bash
docker compose -f docker-compose.yml -f docker-compose.staging.yml \
  --profile staging --profile oast build --no-cache backend worker oast

docker compose -f docker-compose.yml -f docker-compose.staging.yml \
  --profile staging --profile oast up -d
```

**Pass:** כל השירותים `healthy`; `curl -sf http://localhost/api/health`.

---

## 7. QA — ספר 18

```bash
./scripts/staging-qa.sh
./scripts/staging-qa.sh --live http://localhost
```

כולל: wiring, reality audit, UI audit, `cargo check`, smoke live (health, Command Center, capabilities, agent install script).

רשימה מלאה: [18-qa-verification.md](18-qa-verification.md).

---

## 8. וידאו / LMS (אופציונלי)

לא חובה ל-go-live. מומלץ:

- Workshop מוקלט (Command Center + Agent + Billing).
- קישור מספר **00** / חוזה Professional.

---

## טבלת סיכום

| פער | משתנים / קבצים | ספר |
|-----|----------------|-----|
| Paddle `pri_*` | `WEISSMAN_PADDLE_PRICE_*`, SQL example | 08 |
| SMTP signup | `WEISSMAN_SMTP_*`, Mailpit | 06 |
| LLM | `WEISSMAN_LLM_BASE_URL` | 15 |
| OAST | profile `oast`, `WEISSMAN_OAST_*` | 13 |
| Agent binaries | Dockerfile + `package_agent_binaries.sh` | 12 |
| Staging build | `docker-compose.staging.yml` | 02 |
| QA | `scripts/staging-qa.sh` | 18 |
| Video/LMS | workshop | — |

---

## קבצי עזר במאגר

| קובץ | תפקיד |
|------|--------|
| `deploy/env.staging.example` | תבנית `.env` ל-staging |
| `docker-compose.staging.yml` | Mailpit + OAST + env wiring |
| `deploy/go-live/paddle-price-ids.sql.example` | עדכון DB |
| `deploy/oast.Dockerfile` | image ל-OAST |
| `scripts/staging-qa.sh` | QA אוטומטי |
