# Weissman-cybersecurity Enterprise Upgrade — Summary

## Phase 1: Infrastructure & Scalability

### Database (PostgreSQL + Alembic)
- **`src/database.py`**: תומך ב-PostgreSQL עם `DATABASE_URL` (וגם SQLite כ-fallback). מנוע async (`create_async_engine` + `asyncpg`) ל-FastAPI כשמשתמשים ב-PostgreSQL.
- **טבלאות חדשות**: `users` (RBAC + MFA), `system_audit_logs`, `attack_surface_snapshots`. ל-`webhooks` נוסף שדה `secret`.
- **Alembic**: `alembic.ini`, `alembic/env.py`, `alembic/versions/001_initial_postgres.py` — מיגרציה ראשונית ל-PostgreSQL.
- **הרצה**: `export DATABASE_URL=postgresql://weissman:weissman@localhost:5432/weissman` ואז `alembic upgrade head`.

### Task Queue (Redis + Celery)
- **`src/celery_app.py`**: Celery עם Redis כ-broker (`REDIS_URL`).
- **`src/celery_tasks.py`**: משימות `run_scan_task` (קורלציה + דוח) ו-`run_fuzz_task` (הרצת Rust fuzzer). האורקסטרטור (FastAPI) יכול לשלוח משימות; ה-worker מריץ.
- **Docker**: `docker-compose.yml` — שירותים: `db-postgres`, `redis-broker`, `api-backend`, `rust-worker` (Celery worker). `Dockerfile.api`, `Dockerfile.worker`.

---

## Phase 2: Enterprise Security & Auth

### RBAC
- **`UserModel`**: `email`, `password_hash`, `role` (`super_admin`, `security_analyst`, `viewer`).
- **`src/auth_enterprise.py`**: `hash_password`, `verify_password`, `get_user_by_email`, `require_role(min_role)` (dependency ל-FastAPI). היררכיה: super_admin > security_analyst > viewer.

### MFA (TOTP)
- **pyotp** ב-requirements. ב-`UserModel`: `mfa_secret`, `mfa_enabled`. `auth_enterprise.py` מכין יצירת משתמש ברירת מחדל עם סוד TOTP. אינטגרציה מלאה ללוגין (דף MFA אחרי סיסמה) דורשת עדכון ב-`app.py` ו-templates.

### Audit Log
- **`src/audit.py`**: `log_action(action, user_id, user_email, ip_address, details)`. טבלה `system_audit_logs` — כל פעולה (login, scan_trigger, report_download) נרשמת עם timestamp, IP, user_id, פרטים. יש לקרוא ל-`log_action` מכל נקודת קצה רלוונטית (לאחר לוגין, לפני/אחרי הרצת סריקה, בעת הורדת PDF).

### HMAC Webhooks
- **`src/webhooks.py`**: כותרת `X-Weissman-Signature` = HMAC-SHA256 של גוף ה-POST. סוד: `WEBHOOK_SECRET` או `w.secret` לכל webhook. הלקוח יכול לאמת מקוריות.

---

## Phase 3: Advanced Intelligence & Validation

### CVSS & EPSS
- **`src/cvss_epss.py`**: `severity_to_cvss_vector(severity)` מחזיר וקטור CVSS 3.1; `get_epss_score(cve_id)` שולף EPSS מ-API של FIRST. ניתן לצרף ל-findings בדוחות וב-PDF.

### Rust Validator
- **`fingerprint_engine/src/validator.rs`**: אימות עם בדיקות Content-Length (discrepancy ביחס ל-baseline) וניתוח side-channel של headers (שינוי ב-Server, X-Powered-By וכו'). `ValidationBaseline` כולל `content_length`; `confirm_anomaly` מחזיר true רק אחרי 2+ אישורים (כולל length/header).

### Delta-Scanning
- **`src/delta_scan.py`**: `get_snapshot(target_id)`, `has_changed(target_id, ports, headers, cve_ids)`, `save_snapshot(...)`. טבלה `attack_surface_snapshots`. יש לשלב בלולאת האורקסטרציה: לבדוק `has_changed` לפני שליחת התראה, ולעדכן `save_snapshot` אחרי סריקה.

### Tor-Killswitch
- **`src/darkweb_intel.py`**: `_check_tor_connectivity()` — אם החיבור ל-Tor נכשל, מוגדר `_tor_dead = True` ולא מבוצעות עוד בקשות (מניעת דליפת IP). כל `_fetch_url` ו-`_search_sources` בודקים לפני ביצוע.

---

## Phase 4: Elite Reporting (PDF)

- **`src/pdf_export.py`**: עמוד שער עם Weissman Security Rating (צבע: ירוק/צהוב/אדום); Executive Summary; Risk Heatmap 5×5; **Technical Deep-Dive**: טבלת ממצאים עם **CVSS Vector**, **Safe Reproduce (CURL)**, Remediation; **Industry Benchmarking** (השוואה לציון ממוצע ו-percentile); **Digital Integrity Stamp** (SHA-256 + timestamp) בסוף.

---

## How to Run (Enterprise)

1. **PostgreSQL + Redis**:  
   `docker-compose up -d db-postgres redis-broker`

2. **מיגרציה**:  
   `export DATABASE_URL=postgresql://weissman:weissman@localhost:5432/weissman`  
   `alembic upgrade head`

3. **API**:  
   `docker-compose up api-backend` או `uvicorn src.web.app:app --host 0.0.0.0 --port 8000`

4. **Worker**:  
   `celery -A src.celery_app worker -l info -Q default,scan,fuzz -c 4`

5. **שליחת משימה מסריקה**:  
   מ-FastAPI: `from src.celery_tasks import run_scan_task; run_scan_task.delay()` או `run_fuzz_task.delay(url, notify_url)`.

---

## מה נשאר לאינטגרציה מלאה

- חיבור כל ה-routes ב-`app.py` ל-`require_role` (למשל רק `security_analyst` ומעלה יוכלו להריץ סריקה).
- דף לוגין דו-שלבי: סיסמה ואז TOTP, ושמירת session עם `user` ו-`role`.
- קריאות ל-`log_action` מכל הפעולות הרלוונטיות (לוגין, הרצת סריקה, הורדת דוח).
- שילוב `delta_scan.has_changed` / `save_snapshot` בלולאת הסריקה וההתראות.
