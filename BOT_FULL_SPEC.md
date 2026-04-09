# Weissman-Cybersecurity — מפרט מלא של הבוט

**תאריך:** 2026-03-12  
**מטרה:** תיעוד מדויק של מה הבוט עושה, מה עושה חלקית, מה לא עושה, מה הלקוח רואה, ואילו ספריות/רמות סריקה בכל רכיב.

---

## 1. ספריות (Dependencies)

### 1.1 Rust (Cargo.toml)

| חבילה | גרסה | שימוש |
|--------|------|--------|
| **reqwest** | 0.12 (json, native-tls) | כל בקשת HTTP חיצונית: crt.sh, HackerTarget, NPM, PyPI, OSV, Ollama, OpenAPI, TCP. timeout, danger_accept_invalid_certs. |
| **tokio** | 1 (full, sync) | Runtime אסינכרוני; TcpStream, lookup_host, spawn. |
| **regex** | 1.10 | זיהוי meta generator ב-HTML (fingerprint), כללי signatures. |
| **futures** | 0.3 | join_all לסריקות מקבילות. |
| **ipnetwork** | 0.20 | פרסור CIDR לסריקת IP (fingerprint). |
| **urlencoding** | 2.1 | קידוד payload ב-Ollama fuzz, NPM search. |
| **rand** | 0.8 | User-Agent אקראי, proxy אקראי. |
| **axum** | 0.7 (json, ws) | שרת HTTP, WebSocket, routing. |
| **tower**, **tower-http** | 0.4, 0.5 (fs, cors) | CORS, שירת קבצים סטטיים (frontend). |
| **rusqlite** | 0.31 (bundled) | SQLite: clients, users, report_runs, vulnerabilities. |
| **bcrypt** | 0.16 | Hash סיסמאות בהתחברות. |
| **chrono** | 0.4 | תאריכים (Utc). |
| **chrono-tz** | 0.10 | המרה ל־Asia/Jerusalem בהצגה ללקוח. |
| **serde**, **serde_json** | 1 | סריאליזציה לכל ה־API ו־engine results. |
| **tracing** | 0.1 | לוגים ב־fuzzer (error!). |
| **tracing-subscriber** | 0.3 | init ב־CLI fuzz. |

### 1.2 Frontend (package.json)

| חבילה | שימוש |
|--------|--------|
| **react**, **react-dom** | 18.2 | UI חדר מלחמה. |
| **three** | 0.160 | גלובוס 3D (WebGL). |
| **react-window** | 1.8 | גלילה וירטואלית (אם בשימוש). |
| **vite** | 5 | Build; base: `/command-center/`. |
| **tailwindcss** | 3.4 | עיצוב. |

---

## 2. מה הבוט עושה בפועל (מקצה לקצה)

### 2.1 הפעלה

- **פקודה:** `./start_weissman.sh`
- **תוצאה:** טעינת `.env`, יצירת `data/`, בניית `fingerprint_engine` (release), אופציונלי בניית `frontend/dist`, הרצת `fingerprint_engine serve`.
- **תהליך יחיד:** API + דשבורד + WebSocket + Orchestrator ברקע (thread נפרד, כל 60 שניות אם סריקה פעילה).
- **פורט:** 8000 (או משתנה סביבה PORT).
- **DB:** SQLite ב־`data/app.db` (או WEISSMAN_DB_PATH).

### 2.2 מסד נתונים (server_db.rs)

- **clients:** id, tenant_id, name, domains (JSON), ip_ranges, tech_stack, auto_detect_tech_stack, contact_email, created_at, updated_at.
- **users:** id, tenant_id, email, password_hash, role, mfa_secret, mfa_enabled, sso_provider, sso_id, created_at. ברירת מחדל: משתמש אחד (admin@weissman.local / admin) אם הטבלה ריקה.
- **report_runs:** id, tenant_id, region, created_at, findings_json, summary, pdf_path. summary כולל by_severity, total, run_at.
- **vulnerabilities:** id, run_id, tenant_id, client_id, finding_id, title, severity, source, description, status, proof, discovered_at, created_at, updated_at.
- **system_configs (Zero-Config):** key (TEXT PK), value (TEXT), description (TEXT). מפתחות: scan_interval_secs, active_engines (JSON), asm_ports (JSON), asm_port_timeout_ms, osint_timeout_secs, supply_chain_timeout_secs, bola_idor_timeout_secs, ollama_fuzz_timeout_secs, recon_subdomain_prefixes (JSON).
- **אינדקסים:** ix_vuln_run_id, ix_vuln_client_id, ix_vuln_status, ix_report_created, ix_users_email.
- **PRAGMA:** WAL, synchronous=NORMAL, busy_timeout=30000.

### 2.3 אורקסטרטור (server_orchestrator.rs)

- **תדירות:** מרווח הלופ נקרא מ־system_configs (scan_interval_secs, ברירת מחדל 60 שניות); רץ רק אם `scanning_active == true`.
- **הגדרות מ־DB:** active_engines (JSON — אילו מנועים להריץ), asm_ports (JSON — רשימת פורטים ל־ASM), recon_subdomain_prefixes (JSON — רשימת פריפיקסים לסאבדומיינז; אם חסר — DEFAULT_SUBDOMAINS).
- **לוגיקה:** שליפת כל הלקוחות; לכל לקוח לוקחים דומיין ראשון מ־domains (או את name). על ה־target הזה רצים **רק המנועים הפעילים** (לפי active_engines), לפי הסדר:
  1. **osint** — `run_osint_sync(&target)`
  2. **asm** — `run_asm_sync_with_ports_and_subdomains(&target, asm_ports, recon_subdomains)` (פורטים ורשימת סאבדומיינז מ־config)
  3. **supply_chain** — `run_supply_chain_sync(&target)`
  4. **bola_idor** — `run_bola_idor_sync(&target)`
  5. **ollama_fuzz** — `run_ollama_fuzz_sync(&target)`
- **כתיבה:** לכל finding מכל מנוע — INSERT ל־vulnerabilities (run_id, client_id, finding_id, title, severity, source, description='', status='OPEN', discovered_at=now). לא נשמרים proof או מבנה JSON מלא של ה־finding.
- **report_runs:** רשומה אחת לכל מחזור; בסוף עדכון summary (total, run_at).

### 2.4 מנוע OSINT (osint_engine.rs)

- **ספריות:** reqwest (timeout 10s), serde_json.
- **מקורות:**
  - **crt.sh:** `GET https://crt.sh/?q=%.{domain}&output=json` — subdomains מתעודות (name_value / common_name). מסנן: רק רשומות שמסתיימות ב־domain, ללא wildcard, ללא כפילויות.
  - **HackerTarget:** `GET https://api.hackertarget.com/hostsearch/?q={domain}` — hostsearch. מפרסר שורות, לוקח חלק לפני פסיק, מסנן לפי domain.
- **פלט:** מערך findings עם type=osint, source=ct|whois, asset_type=subdomain, value=hostname, confidence, risk_impact, severity=medium.
- **עומק:** רק שני מקורות; אין Dark Web, אין Telegram/Pastebin; אין rate limit מפורש ל־crt.sh.

### 2.5 מנוע ASM (asm_engine.rs)

- **ספריות:** reqwest, tokio (TcpStream, timeout 500ms), fingerprint (scan_targets_concurrent), recon (enum_subdomains_default).
- **פורטים:** 24 פורטים קבועים: 80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 27017, 6379, 9200, 3000, 5000, 8000, 8888, 9443, 111, 135, 139, 445, 1433, 3389, 9000. חומרה: 21,22,3306,6379,1433,3389 → severity high.
- **תהליך:** (1) TCP connect לכל פורט על ה־host. (2) אם host נראה דומיין (לא IP) — enum_subdomains_default (כ־56 subdomains מ־recon), בונים עד 20 subdomains + http/https, קוראים ל־scan_targets_concurrent (fingerprint) ומקבלים tech stack; כל URL עם tech לא ריק → finding מסוג fingerprint.
- **פלט:** findings עם type=asm, asset=port|fingerprint, value=host:port או URL, port (אם רלוונטי), tech_stack (אם fingerprint), severity.

### 2.6 מנוע Supply Chain (supply_chain_engine.rs)

- **ספריות:** reqwest (timeout 8s), urlencoding, serde_json.
- **מקורות:**
  - **NPM:** `GET https://registry.npmjs.org/-/v1/search?text={prefix}&size=50` — prefix = החלק הראשון של הדומיין (לפני הנקודה הראשונה). לכל חבילה שנמצאה — שאילתת OSV.
  - **PyPI:** `GET https://pypi.org/pypi/{pypi_name}/json` — חבילה אחת לפי prefix (עם רווחים → מקף). שאילתת OSV לחבילה.
  - **OSV:** `POST https://api.osv.dev/v1/query` עם body `{ "package": { "name", "ecosystem" } }` — מחזיר מספר vulns; אם >0 → severity high.
- **פלט:** findings עם type=supply_chain, package, ecosystem=npm|pypi, version, vuln_count, typosquat_risk=false, severity=high|info.
- **מגבלה:** אין RubyGems, אין Go; אין בדיקת typosquat אמיתית; NPM מוגבל ל־50 תוצאות.

### 2.7 מנוע BOLA/IDOR (bola_idor_engine.rs)

- **ספריות:** reqwest (timeout 6s), serde_json.
- **תהליך:** (1) חיפוש OpenAPI ב־4 נתיבים: /openapi.json, /swagger.json, /api-docs, /v2/api-docs. (2) פרסור paths; רק paths עם `{param}`. (3) לכל path עם parameters (in=path או שם שמכיל id/uuid/key) — בניית שני URLs: החלפת כל param ב־1 וב־2. (4) שליחת GET לשני ה־URLs; אם לאחד 200 ולשני לא — finding פוטנציאלי BOLA/IDOR.
- **פלט:** findings עם type=bola_idor, path, method, substituted, original_status, sub_status, severity=high.
- **מגבלה:** רק GET/POST; רק path parameters; אין body; אין cookies/auth; בדיקה אחת (1 vs 2) ולא מגוון IDs.

### 2.8 מנוע Ollama Fuzz (ollama_fuzz_engine.rs)

- **ספריות:** reqwest (timeout 6s ל־target, 15s ל־Ollama), urlencoding, serde_json.
- **תנאי:** Ollama חייב לרוץ מקומית ב־http://127.0.0.1:11434.
- **תהליך:** (1) GET ל־target; אוסף headers (12 ראשונים) + 1500 תווים ראשונים מגוף. (2) שליחת prompt ל־Ollama: "הפק רשימת payloads ל־XSS, SQLi, path traversal, שורה אחת לכל payload, עד 25 שורות". ניסיון מודלים: llama3.2, llama2, llama3, mistral, phi עד שמתקבלים payloads. (3) לכל payload — בקשת GET עם query param `q={encoded_payload}`. (4) אם status>=500 או body length>50_000 → finding.
- **פלט:** findings עם type=ollama_fuzz, payload (100 תווים), status, length, severity=high|medium.
- **מגבלה:** רק GET עם query; אין POST body fuzz; אין headers fuzz; 25 payloads מקסימום; תלוי במודל מקומי.

### 2.9 Fingerprint (fingerprint.rs)

- **ספריות:** reqwest, regex, rand, ipnetwork, futures, tokio (TcpStream), tokio::sync::Semaphore.
- **שימוש:** נקרא מ־ASM (scan_targets_concurrent) ומ־CLI (פקודת URL ישירה ו־ips).
- **scan_target_tech:** GET ל־URL; Server header, X-Powered-By, meta name=generator ב־HTML; נורמליזציה (lowercase, גזירת מוצר); החזרת רשימת טכנולוגיות.
- **סטלט':** User-Agent אקראי מ־7 אפשרויות, Accept, Accept-Language; תמיכה ב־PROXIES_LIST / PROXIES_FILE; timeout 10s; danger_accept_invalid_certs.
- **פורט סקן (CLI ips):** top 1000 פורטים (או 3 ברירת מחדל); semaphore 500; timeout 2s ל־TCP; תמיכה ב־--deep.

### 2.10 Recon (recon.rs)

- **ספריות:** tokio (lookup_host), tokio::sync::Semaphore.
- **DEFAULT_SUBDOMAINS:** 56 פריפיקסים (www, mail, admin, api, dev, staging, ...).
- **enum_subdomains:** לכל prefix בונה host = prefix.domain; lookup_host(host:80); concurrency עד 500; מחזיר רשימת hostnames שפתרו.
- **שימוש:** ASM קורא ל־enum_subdomains_default (בלי wordlist חיצוני); עד 20 subdomains נכנסים ל־fingerprint.

### 2.11 Fuzzer (fuzzer.rs) — לא מחובר לדשבורד/אורקסטרטור

- **שימוש:** רק מ־CLI: `fingerprint_engine fuzz <url> [base_payload]`.
- **ספריות:** reqwest, tracing.
- **Mutator:** bit_flip, byte_swap, dangerous_suffix (%00, script, ../../../etc/passwd, וכו'), massive_length (10k, 50k 'A'). אופציונלי: FUZZ_PAYLOADS_FILE.
- **בסיס:** 3 בקשות baseline; מדידת latency, status, content-length. לולאת mutations; אם זמן > baseline*5 או status 500 או אורך שונה משמעותית → anomaly. אופציונלי: התאמה ל־payload_signatures.json ו־validator::confirm_anomaly; אם מאושר → reporter::generate_bug_report (קובץ Markdown ב־reports/).
- **מה לא קורה:** הדשבורד וה־API לא קוראים ל־run_fuzzer; הממצאים לא נשמרים ל־vulnerabilities; רק Ollama Fuzz רץ מהאורקסטרטור.

### 2.12 Validator (validator.rs)

- **שימוש:** רק מתוך fuzzer.rs (בזמן הרצת `fuzz` מ־CLI).
- **לוגיקה:** שליחת payloads משניים (CONFIRMATION_PAYLOADS); השוואת status, latency, content-length, headers (Server, X-Powered-By, וכו'); אם יש אי־התאמה עקבית → confirm.

### 2.13 Reporter (reporter.rs)

- **שימוש:** רק מתוך fuzzer כאשר anomaly מאושר.
- **פלט:** קובץ Markdown ב־reports/anomaly_<timestamp>.md (תבנית HackerOne/Bugcrowd, עם curl PoC). אופציונלי: POST ל־NOTIFY_URL עם שם הקובץ.

### 2.14 Safe Probe (safe_probe.rs)

- **שימוש:** רק מ־CLI: `fingerprint_engine safe-probe <url> [tech_hint]`.
- **לוגיקה:** GET baseline; GET עם X-Forwarded-For, X-Original-URL; השוואת headers ו־timing; החזרת SafeProbeResult (ללא הרצת payload הרסני).
- **לא מחובר:** לא ל־API, לא לאורקסטרטור, לא לדשבורד.

### 2.15 Signatures (signatures.rs)

- **שימוש:** ב־fuzzer — טעינת payload_signatures.json (כללים payload → expected_signature); cache 60s לפי mtime.
- **לא מחובר:** אין קריאה מ־server או מאורקסטרטור.

---

## 3. API (server.rs) — מה הלקוח יכול לקרוא/להפעיל

| Method + Path | תיאור | מקור נתונים |
|---------------|--------|-------------|
| GET / | דשבורד HTML | DB: סטטיסטיקות, טבלאות findings + clients, last_scan per client (Israel time). |
| GET /dashboard | כמו / | כמו למעלה. |
| GET /ws/command-center | WebSocket | בהתחברות: init עם globe (ריק/סטטי), score מ־DB. |
| GET /api/dashboard/stats | JSON סטטיסטיקות | DB: total_vulnerabilities, active_scans (0/1), security_score, assets_monitored, threats_mitigated. |
| GET /api/findings | רשימת ממצאים | DB: עד 500 vulnerabilities (id, finding_id, title, severity, source, status, client). |
| GET /api/reports | רשימת runs | DB: report_runs (id, created_at, pdf_path). |
| GET /api/command-center/ticker | אירועים ל־ticker | DB: עד 100 vulnerabilities כמבנה events (id, time, target, severity, message). |
| POST /api/command-center/scan | הרצת מנוע בודד על target | body: engine, target. מנועים: supply_chain, ollama_fuzz, bola_idor, osint, asm. מחזיר job_id, status, findings, message. |
| POST /api/login | התחברות | body: email, password. bcrypt verify מול users. מחזיר ok, user_id. |
| GET /api/clients | רשימת לקוחות | DB: id, name, domains, tech_stack, ip_ranges. |
| POST /api/clients | יצירת לקוח | body: name, domains?, tech_stack?, ip_ranges?. INSERT ל־clients. |
| POST /api/clients/:id | עדכון לקוח | body: name, domains, tech_stack, ip_ranges. UPDATE. |
| GET /api/clients/:id/export/csv | ייצוא CSV ממצאים ללקוח | DB: vulnerabilities WHERE client_id=:id. קובץ להורדה. |
| GET /api/clients/:id/report/pdf | דוח HTML (Print to PDF) | DB: client name + vulnerabilities ללקוח. HTML עם טבלה; הורדה כ־attachment. |
| GET /api/scan/status | סטטוס סריקה | scanning_active (AtomicBool). |
| POST /api/scan/start | הפעלת סריקה רציפה | set_scanning_active(true). |
| POST /api/scan/stop | עצירת סריקה | set_scanning_active(false). |
| POST /api/scan/run-all | מחזור סריקה אחד מיידי | spawn_blocking(run_cycle). כל הלקוחות, מנועים לפי active_engines. |
| GET /api/system/configs | קבלת כל ההגדרות (Zero-Config) | DB: system_configs (key, value, description). לשימוש ב־React. |
| POST /api/system/configs | עדכון הגדרות (ללא ריסטארט) | body: configs { key: value } או { key, value }. INSERT OR UPDATE. |
| POST /api/command-center/deep-fuzz | Fuzzer + Validator → DB | body: target_url, base_payload?. מריץ run_fuzzer_collect; אנומליות מאומתות נכתבות ל־vulnerabilities (source=deep_fuzz). מחזיר 202 + job_id. |

---

## 4. מה הלקוח רואה — דשבורד (HTML)

- **כותרת:** WEISSMAN CYBERSECURITY, טאגליין "Command Center — live data only".
- **כפתורים:** Dashboard, Open War Room.
- **כרטיסים:** Vulnerabilities (count), Clients (count), Security Score (0–100, מחושב מ־summary אחרון).
- **שליטה:** Start continuous scan, Stop scan, **Run full scan now (all clients, all 5 engines)**. טקסט: "Scans use client domains from the table below. Engines: OSINT, ASM, Supply Chain, BOLA/IDOR, AI Fuzz." סטטוס: Scanning active / Stopped (מעודכן מ־/api/scan/status).
- **טבלת לקוחות:** ID, Name, Domains (מקוצר ל־60 תווים), **Last scan (Israel)** (תאריך/שעה Israel), Actions: PDF, Excel (CSV).
- **טופס:** Add client — name, domains (JSON). שליחה ל־POST /api/clients ו־reload.
- **טבלת ממצאים:** ID (VLN-*), Title, Severity, Source, Client, **Discovered (Israel)**.
- **זמנים:** כל התאריכים המוצגים בדשבורד מומרים ל־Israel (chrono-tz Asia/Jerusalem, פורמט dd/mm/yyyy HH:MM Israel).

---

## 5. מה הלקוח רואה — חדר מלחמה (React)

- **נתיב:** /command-center/ (קבצי build מ־frontend/dist).
- **Command Bar:** רשימת לקוחות מ־/api/clients; בחירת לקוח ממלאת target (דומיין ראשון). שדה טקסט "Or enter URL". כפתור **Scan all clients** → POST /api/scan/run-all. כפתורי מנועים: SC (Supply Chain), AI (Ollama Fuzz), IDOR, OSINT, ASM — שליחה ל־/api/command-center/scan עם engine + target.
- **גלובוס (Three.js):** גלובוס 3D; init מ־WebSocket (globe + score). אירועים מהטיקר יכולים להציג arcs (אם יש התאמה ל־resolveTargetToLatLon).
- **טיקר / Live Intel:** אירועים מ־/api/command-center/ticker + הודעות WebSocket; פורמט: time, target, severity, message; צבע לפי severity.
- **מרכיבים נוספים:** SecurityScoreGauge, KillChainVisualizer, AssetHexGrid, CyberRadar, GlobalThreatTicker, EmergencyAlert, CinematicBackground.

---

## 6. ייצוא ללקוח — PDF ו־Excel

- **PDF:** GET /api/clients/:id/report/pdf מחזיר **HTML** (לא PDF בינארי). כותרת WEISSMAN, שם לקוח, תאריך (UTC), טבלה: ID, Title, Severity, Source. Footer: "Use browser Print → Save as PDF to export." הקובץ נשמר כ־attachment (שם קובץ לפי שם לקוח).
- **Excel:** GET /api/clients/:id/export/csv — CSV עם עמודות ID, Title, Severity, Source, Status, Discovered. שם קובץ: Weissman_findings_client_{id}.csv. פתיחה ב־Excel נתמכת.

---

## 7. מה הבוט יודע לעשות אבל לא עושה (או עושה רק מ־CLI)

| יכולת | איפה קיים | מחובר ל־Dashboard/Orchestrator? |
|--------|-----------|-----------------------------------|
| **Fuzzer (מוטציות, baseline, anomaly)** | fuzzer.rs | לא. רק `fingerprint_engine fuzz <url>`. |
| **Validator (אישור anomaly)** | validator.rs | לא. רק מתוך fuzzer. |
| **Reporter (Markdown + NOTIFY_URL)** | reporter.rs | לא. רק כשמ־fuzz מתגלה anomaly מאושר. |
| **Safe Probe** | safe_probe.rs | לא. רק `fingerprint_engine safe-probe <url>`. |
| **סריקת IP (CIDR, top 1000 פורטים)** | fingerprint.rs + main ips | לא. רק `fingerprint_engine ips <cidr> [--deep]`. |
| **Subdomains (wordlist מותאם)** | recon.rs + main subdomains | לא. ASM משתמש רק ב־enum_subdomains_default (56 פריפיקסים). |
| **Payload signatures (payload_signatures.json)** | signatures.rs, fuzzer | לא. רק בתוך run_fuzzer. |

---

## 8. מה הבוט לא יודע לעשות

- **Dark Web / Telegram / Pastebin:** OSINT רק crt.sh + HackerTarget.
- **ניטור CVE/NVD רציף:** אין אינטגרציה ל־NVD API; OSV משמש רק ב־Supply Chain לחבילות NPM/PyPI.
- **MFA / SSO:** שדות ב־users קיימים; אין לוגיקת login עם MFA או OAuth.
- **RBAC:** אין בדיקת role ב־API; כל המסלולים פתוחים.
- **PDF בינארי:** רק HTML להדפסה; אין ספריית PDF (למשל genpdf).
- **Tenant isolation:** tenant_id קיים בטבלאות; אין סינון לפי tenant ב־queries.
- **Webhooks / Telegram מהשרת:** אין שליחת התראות מהאורקסטרטור; NOTIFY_URL רק ב־reporter (שמופעל רק מ־fuzz).
- **עדכון tech_stack ללקוח:** ASM מחזיר tech_stack ב־findings אבל לא מעדכן את עמודת tech_stack ב־clients.
- **ניהול סטטוס ממצא (OPEN/FIXED וכו'):** שדה status ב־vulnerabilities קיים; אין API או UI לעדכון.

---

## 9. סיכום רמות סריקה / התקפה לפי מנוע

| מנוע | עומק | מגבלות |
|------|------|--------|
| **OSINT** | 2 מקורות (crt.sh, HackerTarget), subdomains בלבד | אין Dark Web; אין rate limit. |
| **ASM** | 24 פורטים TCP; עד 20 subdomains + fingerprint (Server, X-Powered-By, meta generator) | לא top 1000; subdomains רק מ־56 פריפיקסים. |
| **Supply Chain** | NPM 50 חבילות, PyPI חבילה אחת, OSV לכל חבילה | אין Ruby/Go; אין typosquat. |
| **BOLA/IDOR** | OpenAPI ב־4 paths; path params בלבד; החלפה 1/2 | רק GET; אין auth; בדיקה פשוטה. |
| **Ollama Fuzz** | עד 25 payloads מ־AI; GET עם q= | תלוי Ollama מקומי; רק GET query. |

---

## 10. קובץ זה

- **מיקום:** `BOT_FULL_SPEC.md` בשורש הפרויקט.
- **שימוש:** כבסיס להבנה מלאה של הבוט, לתכנון שיפורים, ולתשובות ללקוח על יכולות ומגבלות.
