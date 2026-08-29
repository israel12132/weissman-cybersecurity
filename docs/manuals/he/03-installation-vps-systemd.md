# 03 — התקנה: VPS / Bare Metal (systemd)

## מטרה

פריסת Weissman על שרת Linux בודד **ללא Docker**, עם יחידות systemd native. מסלול זה מתאים כשלקוח דורש שליטה ישירה בתהליכים, tuning של kernel, או build מ-air-gapped.

---

## דרישות מקדימות

| דרישה | מינימום |
|--------|---------|
| OS | Debian 12 / Ubuntu 22.04+ |
| RAM | 8 GB מומלץ (4 GB ל-pilot) |
| CPU | 4 vCPU מומלץ |
| דיסק | 40 GB פנוי |
| תוכנה | Rust 1.91.1, Node 20+, PostgreSQL 16 + pgvector, Redis 7 |
| רשת | Reverse proxy עם HTTPS (nginx או-Caddy) |
| סודות | `WEISSMAN_JWT_SECRET` חזק, סיסמאות DB, סיסמת admin |

---

## שלב אחר שלב

### 1. הכנת השרת

```bash
sudo apt update && sudo apt install -y postgresql-16 redis-server nginx
sudo bash deploy/install-build-deps-debian.sh
sudo bash deploy/apply-listen-sysctl.sh   # somaxconn=4096 — אחרת listen(4096) נחתך בשקט
```

יצירת roles וDB:

```bash
sudo -u postgres psql -f deploy/grant-postgres-weissman-prod.sql
```

### 2. Build של בינארים וfrontend

```bash
git clone https://github.com/israel12132/weissman-cybersecurity.git
cd weissman-cybersecurity
cargo build --release -p weissman-server -p weissman-worker
cd frontend && npm ci && npm run build && cd ..
```

### 3. התקנת יחידות systemd

משורש המאגר:

```bash
sudo bash deploy/systemd/install-weissman-systemd.sh
```

נתיב מותאם:

```bash
sudo INSTALL_ROOT=/srv/weissman/app bash deploy/systemd/install-weissman-systemd.sh
```

| יחידה | תפקיד |
|-------|--------|
| `weissman-server.service` | API Axum + Command Center סטטי מ-`frontend/dist` |
| `weissman-worker.service` | מעבד jobs מ-`weissman_async_jobs` |
| `weissman.target` | קיבוץ שני השירותים |

**אין** תהליך frontend נפרד — build פעם אחת והגשה מ-`WEISSMAN_STATIC`.

### 4. הגדרת סביבה

```bash
sudo cp deploy/systemd/weissman.env.example /etc/weissman/weissman.env
sudo chmod 600 /etc/weissman/weissman.env
sudo nano /etc/weissman/weissman.env
```

**מינימום production:**

```bash
WEISSMAN_ENV=production
WEISSMAN_COOKIE_SECURE=1
DATABASE_URL=postgres://weissman_app:STRONG@127.0.0.1:5432/weissman
WEISSMAN_AUTH_DATABASE_URL=postgres://weissman_auth:STRONG@127.0.0.1:5432/weissman
WEISSMAN_MIGRATE_URL=postgres://postgres:STRONG@127.0.0.1:5432/weissman
WEISSMAN_JWT_SECRET=<openssl rand -base64 48>
REDIS_URL=redis://127.0.0.1:6379/0
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
WEISSMAN_ADMIN_PASSWORD=<סיסמה-חזקה>
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
WEISSMAN_METRICS_TOKEN=<openssl rand -base64 48>
WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET=<openssl rand -base64 48>
PORT=8000
```

ראו ספר **06** לרשימה מלאה.

### 5. Reverse proxy

העתיקו `deploy/nginx-weissman.conf` או-`deploy/Caddyfile`. הפנו TLS ל-`127.0.0.1:8000`.

WebSocket: `deploy/nginx-snippet-websocket-map.conf`.

דחיסת JSON ב-Brotli היא ב-nginx (לא ב-Axum). אחרי `apt install libnginx-mod-http-brotli`:

```bash
sudo cp deploy/nginx-brotli.inc /etc/nginx/snippets/weissman-brotli.conf
```

### 6. הפעלה

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now weissman-server weissman-worker weissman.target
```

Postgres מקומי — override:

```bash
sudo systemctl edit weissman-server
```

```ini
[Unit]
After=postgresql.service
Requires=postgresql.service
```

### 7. אריזת בינארי Agent (אם נמכר)

```bash
bash scripts/package_agent_binaries.sh
```

מתקינים: `GET /install/agent.sh`, `GET /install/agent.ps1`.

---

## אימות

```bash
curl -sf https://your-domain.example/api/health
curl -sf https://your-domain.example/command-center/
sudo systemctl status weissman-server weissman-worker
journalctl -u weissman-server --since "5 min ago" | tail -20
```

התחברות ב-`/command-center/login` עם `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`.

הריצו סריקת smoke; ו worker תופס את ה-job.

Guards של `security_startup.rs` מסרבים boot עם סודות חלשים כש-`WEISSMAN_ENV=production`.

---

## שדרוג

```bash
cd /opt/weissman/app && git pull
cargo build --release -p weissman-server -p weissman-worker
cd frontend && npm ci && npm run build && cd ..
sudo systemctl restart weissman-server weissman-worker
```

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| Server יוצא מיד | `journalctl -u weissman-server` — JWT, guards |
| 502 מ-nginx | `PORT` תואם upstream; `deploy/fix-weissman-502.sh` |
| Jobs תקועים | Worker לא רץ |
| UI 404 | rebuild frontend; `WEISSMAN_STATIC` |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [02-installation-docker](02-installation-docker.md)
- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [16-operations-monitoring](16-operations-monitoring.md)
- `deploy/systemd/README.md`
