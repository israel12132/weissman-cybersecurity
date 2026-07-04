# 02 — התקנה: Docker Compose (מומלץ)

## מתי להשתמש

- POC, staging, ורוב פריסות production
- צומת בודד או cluster קטן
- הנתיב המהיר ביותר ל-Command Center עובד

---

## דרישות מקדימות

| דרישה | מינימום |
|--------|---------|
| Docker | 24+ |
| Docker Compose | v2 |
| RAM | 4 GB (8 GB מומלץ) |
| דיסק | 20 GB פנוי |
| פורטים | 80 (gateway), פנימי 5432/6379/8000 |

---

## שלב אחר שלב

### 1. Clone והגדרת סודות

```bash
git clone https://github.com/israel12132/weissman-cybersecurity.git
cd weissman-cybersecurity
cp PRODUCTION.env.template .env
```

ערכו `.env` — **מינימום להפעלת compose:**

```bash
openssl rand -base64 48   # → WEISSMAN_JWT_SECRET

WEISSMAN_JWT_SECRET=<הדבק>
WEISSMAN_ADMIN_PASSWORD=<סיסמה-חזקה-12+-תווים>
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
```

ל-**production**, גם (ספר 05):

```bash
WEISSMAN_ENV=production
WEISSMAN_COOKIE_SECURE=1
WEISSMAN_METRICS_TOKEN=<openssl rand -base64 48>
DB_APP_PASSWORD=<חזק>
DB_AUTH_PASSWORD=<חזק>
POSTGRES_PASSWORD=<חזק>
```

### 2. Build והפעלה

**פקודה אחת (מומלץ ללקוחות — אמת לייב):**

```bash
./start_weissman_live.sh --url https://your-company.example
```

**ידני (equivalent):**

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile monitoring up -d --build
```

שירותים:
- `postgres` — pgvector/pg16
- `redis`
- `backend` — weissman-server + migrations
- `worker` — weissman-worker
- `gateway` — nginx

### 3. אימות

```bash
curl -sf http://localhost/api/health
curl -sf http://localhost/command-center/
docker compose ps
docker compose logs backend --tail 30
```

### 4. התחברות

פתחו: **http://localhost/command-center/login**

- אימייל: `WEISSMAN_ADMIN_EMAIL`
- סיסמה: `WEISSMAN_ADMIN_PASSWORD`

**שנו סיסמה מיד** אחרי login ראשון.

---

## פרופיל monitoring (אופציונלי)

```bash
docker compose --profile monitoring up -d
```

Prometheus + Grafana — ספר 16.

---

## משתני compose עיקריים

| משתנה | תפקיד |
|--------|--------|
| `WEISSMAN_MIGRATE_URL` | migrations אוטומטיות |
| `WEISSMAN_PUBLIC_BASE_URL` | URL ציבורי |
| `WEISSMAN_BILLING_STRICT` | פעיל ב-production |
| `PADDLE_*` | Billing — ספר 08 |

---

## שדרוג

```bash
git pull
docker compose up -d --build
```

---

## הסרה (מוחקת נתונים)

```bash
docker compose down -v   # ⚠️ מוחק volume של Postgres
```

---

## תקלות

| תסמין | פתרון |
|--------|--------|
| Compose exit 15 | בדקו `.env`, הציטוט של משתנים עם `:` |
| Backend unhealthy | `docker compose logs backend` |
| 502 על /api | המתינו ל-healthcheck |
| Jobs תקועים | `docker compose restart worker` |

ספר [17-troubleshooting](17-troubleshooting.md).

---

## קשור

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
