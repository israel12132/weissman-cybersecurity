# ביקורת מלאה – Security Assessment Platform (למוכר ל-Google, Tesla וכו')

מסמך זה עובר קובץ-קובץ על כל הפרויקט: **מה יש**, **מה חסר**, **מה להוסיף**, **מה לשפר** – ברמת פרטים למוכר שירות לחברות Enterprise.

---

## 1. מבנה הפרויקט (מה יש)

| נתיב | תיאור |
|------|--------|
| `src/` | ליבת Python: מודלים, DB, קורלציה, feeds, fingerprint wrapper, alerts, darkweb, exploit matcher, threat intel, webhooks, PDF export |
| `src/feeds/` | NVD, GitHub, OSV, OTX, HIBP – משיכת ממצאים ממקורות חיצוניים |
| `src/web/` | FastAPI: app.py (כל ה-routes), auth (session cookie), templates, static |
| `fingerprint_engine/` | Rust: fingerprint (סריקת פורטים + headers + meta), fuzzer, validator, reporter, safe_probe |
| `data/` | SQLite (app.db), reports_pdf |
| `reports/` | דוחות Fuzzer (anomaly_*.md), דוחות HTML/JSON מהרצה ידנית (אם מריצים מ-CLI) |

---

## 2. קובץ-קובץ – מה יש ומה חסר

### 2.1 `src/database.py`

**יש:**
- `ClientModel`: name, domains, ip_ranges, tech_stack, contact_email.
- `ReportRunModel`: findings_json, summary, אינדקס על created_at.
- `WebhookModel`: url, enabled – לשליחת findings ל-Jira/Splunk.
- `AlertSentModel`: target, finding_id, alerted_at – דדופ 24h להתראות Telegram.
- `init_db()` עם יצירת אינדקסים.

**חסר / לשפר:**
- אין גרסת schema (migrations) – שינוי מבנה ידרוש עדכון ידני או כלי migrations.
- אין שדה `notes` או `tags` ללקוח.
- אין טבלת `audit_log` (מי שינה מה ומתי) – חשוב ל-Enterprise.
- Webhook: אין שדה `secret` ל-HMAC חתימה על ה-POST (בטיחות).

---

### 2.2 `src/models.py`

**יש:**
- `Severity`, `FindingType`, `Finding`, `ClientFinding`.
- `Finding.matches_tech_stack` / `matched_tech_stack` עם alias (python/pypi, node/npm).

**חסר / לשפר:**
- אין `CVSS vector` או `EPSS` – רק severity מוגדר. ל-Enterprise כדאי שדה cvss_score או vector.
- אין `status` לממצא (open, acknowledged, fixed, false positive) – נדרש ל-workflow.

---

### 2.3 `src/config.py`

**יש:**
- Pydantic: Scope, Client, NVD/GitHub/OSV/OTX/HIBP, Reporting, Scheduler.
- `load_config(path)` – משמש רק את `main.py` ו-`scheduler.py`.

**חסר:**
- בדשבורד **לא** נטען config.yaml – כל המפתחות מ-`.env`. תיעוד ברור ב-README/SUMMARY שיש שני מסלולים (CLI=config, Web=.env).
- אין validation ל-URLים (domains, webhook) ב-config.

---

### 2.4 `src/correlation.py`

**יש:**
- `correlate_findings_to_clients(config)` – מ-config (CLI).
- `correlate_findings_from_db(db_clients, intel_config)` – מ-DB + env.
- Fingerprinting (URLs + IP ranges) לפני קורלציה, merge ל-tech_stack.
- HIBP per-domain ללקוח.
- `dedupe_by_finding_id`.

**חסר / לשפר:**
- אין cache ל-feed results (כל 5 דקות מושכים מחדש מכל ה-APIs – עלול להביא ל-rate limit).
- אין retry עם backoff ל-feeds שנכשלו.
- intel_config נבנה רק מ-env – אין אפשרות לכבות feed בודד מהדשבורד (רק ב-config.yaml ל-CLI).

---

### 2.5 Feeds (`src/feeds/`)

**NVD:** 30 יום אחרונים, 200 תוצאות, apiKey אופציונלי. מפת severity מ-CVSS.  
**GitHub:** 50 advisories, token חובה לריצה טובה.  
**OSV:** 20 מ-CSV, fallback ל-query לפי חבילות.  
**OTX:** 30 pulses, דורש API key.  
**HIBP:** רק per-domain ב-correlation, לא ב-fetch().

**חסר בכל ה-feeds:**
- אין rate limit מובנה (רק ב-threat_intel יש sleep).
- אין שמירת `last_modified` / etag לצמצום קריאות.
- NVD: ללא API key יש הגבלה חזקה – מומלץ להזכיר ב-README.

---

### 2.6 `src/fingerprint.py`

**יש:**
- קריאה ל-Rust binary (release/debug), fingerprint_urls, fingerprint_ip_ranges.
- run_fuzzer_binary (Popen ברקע, NOTIFY_URL ב-env).
- run_safe_probe.
- merge_fingerprint_into_scope.

**חסר / לשפר:**
- timeout 60s ל-URLs, 300s ל-IPs – קבוע. ל-Enterprise אולי config.
- אם הבינארי לא קיים – מחזיר {} בשקט; כדאי log או הודעה בדשבורד.

---

### 2.7 `src/alerts.py`

**יש:**
- Telegram send עם dedup 24h (AlertSentModel).
- format ו-send ל-CVE, fuzzer, exploit, darkweb.

**חסר / לשפר:**
- אין retry על כישלון שליחה.
- אין תמיכה ב-Slack / PagerDuty / אימייל – רק Telegram.
- SECRET_KEY ב-auth לא קשור לחתימת webhook – מומלץ להזכיר ב-docs.

---

### 2.8 `src/darkweb_intel.py`

**יש:**
- Tor proxy (socks5h://127.0.0.1:9050), Session עם headers.
- search_domain_dumps, search_tech_exploit_mentions, search_company_leaks.
- מקורות מ-env (DARKWEB_SOURCES) או ahmia/onion.live.
- לוג שגיאות, לא קורס.

**חסר:**
- אין וידוא ש-Tor רץ – אם לא, הבקשות נכשלות בשקט.
- מקורות ברירת מחדל הם clearnet indexers, לא .onion ישיר – תיעוד.

---

### 2.9 `src/exploit_matcher.py` + `src/threat_intel.py`

**יש:**
- חיפוש GitHub (exploit/poc/payload + tech), בלי סינון תאריך.
- TECH_ALIASES, match_exploit_to_target, filter_matching_exploits.

**חסר / לשפר:**
- GitHub rate limit – עם token 30/min בערך; אין queue או backoff מסודר.
- אין שמירת "כבר בדקנו repo X ללקוח Y" – כל מחזור שוב מאותם ריפואים.

---

### 2.10 `src/webhooks.py`

**יש:**
- build_webhook_payload (report_id, timestamp, summary, findings עם cvss_score, remediation).
- push_findings_to_webhooks – POST ל-all enabled, timeout 15s, לוג שגיאות.

**חסר / לשפר:**
- אין חתימת HMAC ב-header (למשל X-Signature) – Jira/Splunk לא יוכלו לוודא מקור.
- אין retry (למשל 2 ניסיונות).
- אין webhook-level secret (להצפנה/חתימה).

---

### 2.11 `src/pdf_export.py`

**יש:**
- CVSS 1–10 מ-anomaly type + severity.
- Remediation טקסט לפי סוג אנומליה.
- WeasyPrint, HTML → PDF, שמירה ב-data/reports_pdf.

**חסר / לשפר:**
- אין לוג כשנכשל (return None).
- אין PDF לדוח Fuzzer בודד (רק ל-report run של CVE).
- CVSS הוא heuristic פשוט – לא CVSS 3.1 מלא; בתיעוד להבהיר.

---

### 2.12 `src/web/auth.py`

**יש:**
- Session ב-cookie (itsdangerous), 24h.
- require_auth (cookie או Bearer).

**חסר / לשפר:**
- SECRET_KEY ברירת מחדל "change-me-in-production" – חובה להגדיר ב-production.
- אין 2FA, אין RBAC (כולם admin).
- אין rate limit על login – חשוב ל-Enterprise.

---

### 2.13 `src/web/app.py`

**יש:**
- Lifespan: scheduler כל 5 דקות + thread אינסופי (darkweb → CVE → recon/fuzz → exploit).
- Routes: login, dashboard, clients CRUD, attack/fuzz per client, run assessment, reports, report detail, PDF, webhooks, fuzzer-reports.
- Webhook push אחרי כל שמירת דוח (auto + manual).
- Exception handlers ל-401/404/500.

**חסר / לשפר:**
- load_dotenv ב-login עם path `parent.parent.parent` – עלול להיות שבור אם מבנה התיקיות שונה; עדיף BASE_DIR אחד.
- אין rate limit על POST /run ו-POST /clients (סיכון DoS).
- אין API רשמי (OpenAPI) ל־"push findings" – רק webhook קורא ל-URL של הלקוח.
- לולאת האורקסטרציה רצה כל 0.5s – צפוף; אפשר 5–10s בין מחזורים מלאים כדי להפחית עומס.

---

### 2.14 `src/reports.py`

**יש:**
- generate_json_report, generate_html_report, run_report (stamp, json/html).
- report_by_client, _sort_findings.

**חסר:**
- הדשבורד לא משתמש ב-generate_html_report ל-CVE – הדוחות נשמרים ב-DB ומוצגים מתבניות. הקובץ רלוונטי ל-CLI (main.py).
- אין פורמט PDF כאן – PDF רק מ-pdf_export לדף דוח ב-web.

---

### 2.15 `src/scheduler.py` + `main.py`

**יש:**
- הרצה לפי config (config.yaml), IntervalTrigger לפי שעות.
- main.py: single run או --hourly.

**חסר:**
- אין שימוש ב-.env כאן – רק config.yaml. אז ל-CLI צריך גם להעביר מפתחות (או לקרוא .env ב-main).

---

### 2.16 Rust – `fingerprint_engine`

**fingerprint.rs:**  
- סריקת פורטים async (top 1000), Semaphore 500, stealth headers, Server/X-Powered-By/meta generator.  
- IP range (CIDR), בניית URLs מפורטים פתוחים.

**fuzzer.rs:**  
- Mutator (bit flip, byte swap, dangerous suffixes, massive length).  
- Baseline, anomaly (500, time x5, length).  
- **Validator** – רק אחרי אישור עם payloads משניים → reporter.

**validator.rs:**  
- CONFIRMATION_PAYLOADS שונה מהפוזר.  
- confirm_count >= 2 → confirmed.  
- חסר: אם anomaly הוא רק Content-Length, ה-validator לא סופר אותו (רק 500 ו-time) – אז Content-Length לא מאומת.

**reporter.rs:**  
- תבנית Markdown, שמירה ל-reports/, POST ל-NOTIFY_URL עם filename.

**safe_probe.rs:**  
- GET baseline + GET עם X-Forwarded-For/X-Original-URL, השוואת headers ו-timing.

**חסר ב-Rust:**
- אין קונפיגורציה מקובץ (כל הקבועים בקוד).
- reporter: reports/ יחסי ל-cwd – אם מריצים ממקום אחר עלול להיכתב בתיקייה לא צפויה.

---

### 2.17 תבניות (templates)

**יש:** base (nav), dashboard, clients, client_form, reports, report_detail, login, fuzzer_report_detail, webhooks.  
**חסר:**  
- רוב הממשק בעברית (rtl) – ל-Enterprise בינלאומי כדאי i18n או גרסה אנגלית.  
- אין תבנית "הגדרות" (Settings) – רק Webhooks.  
- אין תצוגת לוגים / סטטוס תהליכים (איזה job רץ עכשיו).

---

### 2.18 קבצי תצורה והרצה

**יש:**  
- config.example.yaml, .env.example, .gitignore (.env).  
- run_web.py (פורט דינמי), start_public.sh (Cloudflare Tunnel, המתנה לשרת).

**חסר:**  
- .env.example – לוודא שמכיל TELEGRAM_*, DARKWEB_SOURCES, SECRET_KEY, וכל המפתחות המתועדים.  
- אין Dockerfile/docker-compose – התקנה ידנית.  
- start_public.sh: אם השרת בוחר 8001/8002, ה-PORT מתעדכן אבל הודעת "פורט מועדף 8000" עלולה לבלבל.

---

## 3. מה להוסיף (למכירה ל-Google / Tesla)

1. **אבטחה ואמינות**
   - **SECRET_KEY** חובה ב-production (וולידציה ב-startup).
   - **Rate limit** על login ו-POST /run.
   - **Webhook signing**: HMAC של גוף ה-POST ב-header (למשל X-Webhook-Signature).
   - **2FA** (TOTP) או אינטגרציה ל-SSO (SAML/OIDC) – לפי דרישות Enterprise.

2. **מודל נתונים**
   - **Finding status**: open / acknowledged / fixed / false_positive.
   - **Audit log**: מי עשה מה ומתי (יצירת/עדכון/מחיקת לקוח, הרצת בדיקה).
   - **גרסאות schema** (migrations) – Alembic או דומה.

3. **דוחות ו-SLA**
   - **PDF גם לדוח Fuzzer בודד** (anomaly_*.md → PDF עם CVSS + Remediation).
   - **ייצוא Excel/CSV** של טבלת ממצאים.
   - **סיכום SLA**: X ממצאים ב-24h, זמן תגובה ממוצע – אם רוצים להציג ב-dashboard.

4. **אינטגרציות**
   - **Slack / PagerDuty / אימייל** בנוסף ל-Telegram.
   - **API רשמי** (REST): GET /api/v1/findings, POST /api/v1/run – עם API key.
   - **תבנית Jira** מוכנה (מבנה JSON שמתאים ל-Jira Cloud API).

5. **ביצועים ו-stability**
   - **Cache ל-feeds** (למשל 5 דקות) עם invalidation.
   - **Retry + backoff** ל-feeds ו-webhooks.
   - **הרחבת מרווח לולאת האורקסטרציה** (למשל 5–10s) להפחתת עומס.

6. **תיעוד ו-compliance**
   - **README** באנגלית עם Architecture, Deployment, Environment variables.
   - **מסמך התאמה** (compliance): אילו נתונים נשמרים, איפה, retention.
   - **Changelog / גרסאות** – לספק ללקוח.

7. **Rust**
   - **Validator**: לתמוך באישור גם ל-Content-Length anomaly (להגדיר confirm גם על length).
   - **נתיב reports/** – לקבוע לפי env או ארגומנט (לא רק cwd).

8. **ממשק**
   - **שפה**: בחירת שפה (עברית/אנגלית) או דף אנגלית מלא.
   - **דף Settings**: SECRET_KEY לא להציג; להציג סטטוס Tor, סטטוס feeds (אחרון success), רשימת webhooks עם סטטוס אחרון.

---

## 4. סיכום טבלאי – "מה יש / מה אין"

| נושא | יש | חסר/לשפר |
|------|-----|-----------|
| CVE מ-NVD/GitHub/OSV/OTX | ✅ | Cache, retry |
| HIBP per-domain | ✅ | - |
| Fingerprint (Rust) | ✅ | config ל-timeout/ports |
| Fuzzer + Validator | ✅ | Validator ל-Content-Length |
| Safe Probe | ✅ | - |
| Dark Web (Tor) | ✅ | וידוא ש-Tor רץ, תיעוד |
| Exploit GitHub | ✅ | Rate limit, cache ריפואים |
| Telegram alerts | ✅ | Retry, Slack/Email |
| Webhooks (POST) | ✅ | HMAC, retry, secret |
| PDF report | ✅ | PDF ל-Fuzzer, לוג שגיאות |
| CVSS/Remediation | ✅ | CVSS 3.1 מלא (אופציונלי) |
| DB (SQLite) | ✅ | Migrations, audit_log, finding status |
| Auth (cookie) | ✅ | 2FA, rate limit, SECRET חובה |
| Dashboard (CRUD) | ✅ | i18n, דף Settings |
| API רשמי | ❌ | GET/POST עם API key |
| Docker | ❌ | Dockerfile, docker-compose |
| RBAC | ❌ | תפקידים והרשאות |

---

## 5. עדכון SUMMARY.md

ב-SUMMARY.md בסעיף "מה הבוט לא עושה" עדיין מופיע:
- "דוח PDF/אימייל – יש תמיכה ב־WeasyPrint... בדשבורד הדוחות הם בממשק ווב בלבד"  
**זה לא עדכני** – יש כפתור Export PDF בדוח CVE. יש לעדכן ש-PDF קיים ולהוסיף שחסר: PDF לדוח Fuzzer בודד, ייצוא Excel/CSV.

---

סיום הביקורת. מסמך זה משמש כ-**מפת דרכים** לשיפור והשלמת פיצ'רים לפני מכירה ל-Enterprise (Google, Tesla וכו').
