# 06 — הגדרת סביבה (Environment)

## מטרה

מדריך למשתני הסביבה של Weissman. מקור אמת: **`PRODUCTION.env.template`** בשורש המאגר.

---

## דרישות מקדימות

- נתיב פריסה (Docker, systemd, K8s)
- אחסון סודות (vault, `/etc/weissman/weissman.env` chmod 600)
- הבנת guards (ספר **05**)

---

## מיקומי קבצים

| פריסה | קובץ |
|--------|------|
| Docker Compose (`./start_weissman.sh`) | `.env` (מ-`PRODUCTION.env.template`) |
| systemd (בלי Docker) | `/etc/weissman/weissman.env` |
| Kubernetes | ConfigMap + Secret |
| Override | `WEISSMAN_ENV_FILE` (נטען אחרון — גובר על כולם) |

Docker Compose **דורש** מינימום:

```bash
WEISSMAN_JWT_SECRET=<חזק>
WEISSMAN_ADMIN_PASSWORD=<חזק-12+>
```

### איך הקבצים מתמזגים

- ערך **ריק** (`DATABASE_URL=`) אינו ערך. `PRODUCTION.env.template` משאיר את כתובות ה-datastore
  ריקות כי Compose מזריק אותן לכל קונטיינר, ולכן הטוען מתעלם מהשורות האלה לגמרי: הן לא מוחקות
  ערך שכבר קיים בסביבת התהליך ולא מגדירות משתנה כמחרוזת ריקה. בזכות זה
  `WEISSMAN_AUTH_DATABASE_URL` ריק חוזר ל-`DATABASE_URL` כמתועד, במקום להפוך ל-DSN ריק.
- קבצים מאוחרים גוברים על מוקדמים, ו-`WEISSMAN_ENV_FILE` נטען **אחרון** — כך שקובץ שבחר המפעיל
  גובר על כל מיקום מובלע.
- `WEISSMAN_ENV_PROCESS_WINS=1` הופך את הכיוון עבור מעטפות (יחידות systemd שמייצאות
  `DATABASE_URL` ואז `exec` לבינארי): קבצי env רק ממלאים חוסרים ולעולם לא מחליפים ערך שכבר
  נמצא בסביבת התהליך. בלי זה, `PORT=9999 weissman-server` עדיין נקשר ל-`:8000` מתוך `.env`.
- `./start_weissman.sh` הוא Docker-first: הוא לא טוען `.env.local` לתוך תהליכי מארח.
  Compose מזריק `DATABASE_URL`, `WEISSMAN_AUTH_DATABASE_URL`,
  `WEISSMAN_READ_ONLY_DATABASE_URL` ו-`REDIS_URL` מסיסמאות התפקידים ב-`.env`.

---

## שלב אחר שלב: קונפיגורציה ראשונה

### 1. העתקת template

```bash
cp PRODUCTION.env.template .env
# systemd:
sudo cp deploy/systemd/weissman.env.example /etc/weissman/weissman.env
sudo chmod 600 /etc/weissman/weissman.env
```

### 2. משתני ליבה

```bash
WEISSMAN_ENV=production
WEISSMAN_COOKIE_SECURE=1
PORT=8000

DATABASE_URL=postgres://weissman_app:PASS@host:5432/weissman
WEISSMAN_AUTH_DATABASE_URL=postgres://weissman_auth:PASS@host:5432/weissman
WEISSMAN_MIGRATE_URL=postgres://postgres:PASS@host:5432/weissman
REDIS_URL=redis://host:6379/0
```

אופציוני: `WEISSMAN_INTEL_DATABASE_URL`.

### 3. אימות bootstrap

```bash
WEISSMAN_JWT_SECRET=<מינימום-32>
WEISSMAN_ACCESS_TOKEN_MINUTES=15
WEISSMAN_REFRESH_TOKEN_DAYS=30
WEISSMAN_ADMIN_EMAIL=admin@company.com
WEISSMAN_ADMIN_PASSWORD=<החלף-אחרי-login>
```

Bootstrap חד-פעמי: `WEISSMAN_MASTER_BOOTSTRAP_EMAIL`, `WEISSMAN_MASTER_BOOTSTRAP_PASSWORD`.

### 4. URL ציבורי

```bash
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
WEISSMAN_STATIC=/opt/weissman/app/frontend/dist
```

### 5. Worker concurrency

```bash
WEISSMAN_WORKER_LIGHT_CONCURRENCY=8
WEISSMAN_WORKER_HEAVY_CONCURRENCY=2
```

### 6. Billing (Paddle)

```bash
PADDLE_API_KEY=
PADDLE_ENVIRONMENT=production
PADDLE_WEBHOOK_SECRET=
WEISSMAN_BILLING_STRICT=
```

Strict פעיל → `gate_scan_enqueue` חוסם סריקות ללא מנוי.

### 7. אבטחה

```bash
WEISSMAN_METRICS_TOKEN=
WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET=
```

Header: `X-Weissman-Destructive-Confirm`.

### 8. יכולות אופציונליות

| משתנה | השפעה |
|--------|--------|
| `WEISSMAN_LLM_BASE_URL` | Council, NL query |
| `WEISSMAN_ALERT_WEBHOOK_URL` | Webhook התראות |
| `WEISSMAN_PAGER_WEBHOOK_URL` | PagerDuty |
| `WEISSMAN_SMTP_*` | אימייל |
| `WEISSMAN_INTEL_KEV_ENABLED` | KEV (ברירת מחדל on) |
| `WEISSMAN_LOG_FORMAT=json` | לוגים מובנים |

טבלה מלאה: `/docs/operations.md`.

---

## קבוצות לפי נושא

### חובה ל-boot production

- `WEISSMAN_ENV=production`
- `WEISSMAN_JWT_SECRET` (≥ 32, לא placeholder)
- `DATABASE_URL`, `WEISSMAN_COOKIE_SECURE=1`
- `WEISSMAN_MIGRATE_URL`, `WEISSMAN_METRICS_TOKEN`, `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` (server)

### מומלץ בחום

- `REDIS_URL`, `WEISSMAN_AUTH_DATABASE_URL`, `WEISSMAN_PUBLIC_BASE_URL`

### dev בלבד (לעולם לא production)

- `WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1`
- `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1`
- `WEISSMAN_SIGNUP_RETURN_LINK=1`
- `WEISSMAN_ALLOW_INSECURE_TLS=1`

---

## אימות

```bash
docker compose config | grep WEISSMAN_ENV
sudo grep WEISSMAN_ENV /etc/weissman/weissman.env
curl -sf https://your-domain.example/api/health
journalctl -u weissman-server | grep -i migrat
```

סיבוב JWT secret מבטל sessions קיימות.

---

## ספרים קשורים

- [02-installation-docker](02-installation-docker.md)
- [05-production-security](05-production-security.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- `/PRODUCTION.env.template`
