# ביקורת מלאה: Weissman-cybersecurity — כל קובץ וכל שורה

מסמך זה עובר על כל קבצי המקור בפרויקט, מתאר **מה כל קובץ עושה**, **איך הוא עושה**, **מה הוא יודע לעשות אבל עדיין לא ממומש**, ו**מה דורש עוד עבודה**.

---

## 1. שורש הפרויקט

### `run_web.py`
- **עושה:** מכניס את שורש הפרויקט ל־`sys.path`, בודק פורט פנוי (8000, 8001, 8002), ומריץ את אפליקציית FastAPI דרך `uvicorn` על `src.web.app:app`. משתנה `PORT` מ־env, אופציה `RELOAD` ל־hot reload.
- **איך:** `uvicorn.run(..., host="0.0.0.0", port=port)`.
- **חסר:** הודעות ההפעלה עדיין בעברית; אין טעינה מפורשת של `.env` (מסתמך על הטעינה במקומות אחרים).
- **עבודה נדרשת:** תרגום הודעות לאנגלית אם רוצים UI אחיד; אפשר להוסיף `load_dotenv()` כאן כדי להבטיח .env טעון.

### `main.py`
- **עושה:** נקודת כניסה ל־CLI עם Typer. תומך ב־`--config` (config.yaml) ו־`--hourly` (הרצה כל שעה). בלי `--hourly`: מריץ קורלציה אחת (`correlate_findings_to_clients`), dedupe, ו־`run_report` (כתיבת דוח ל־output_dir).
- **איך:** משתמש ב־`src.config`, `src.correlation`, `src.reports`, `src.scheduler`. **לא** מחובר ל־DB של הדשבורד — רק ל־config.yaml.
- **חסר:** אין סנכרון עם מסד הדשבורד (SQLite/PostgreSQL). הרצה מ־CLI ו־הרצה מהדשבורד הן שני ערוצים נפרדים.
- **עבודה נדרשת:** אם רוצים "מקור אמת אחד" — לחבר את main.py ל־DB או להפסיק להשתמש ב־config.yaml ולהפנות הכל לדשבורד/Celery.

### `start_weissman.sh`
- **עושה:** הפעלה מלאה: הפעלת venv, טעינת .env, הפעלת Redis (systemd / Docker / redis-server), הפעלת Celery worker + beat (ל־logs/worker.log, logs/beat.log), בניית מנוע Rust אם חסר, הרצת `run_web.py` ב־foreground. Ctrl+C מפעיל cleanup והורג את תהליכי Celery.
- **איך:** פונקציות `redis_healthy`, `wait_for_redis`, ניסיונות הפעלת Redis לפי סדר, `trap cleanup INT TERM EXIT`.
- **חסר:** אם Redis לא עולה — הסקריפט נכשל (אלא אם `WEISSMAN_FORCE_START=1`). אין הפעלה אוטומטית של `start_public.sh` (tunnel) — רק אם קוראים לו ידנית.
- **עבודה נדרשת:** אופציונלי: אם קיים `start_public.sh` להציע להריץ גם אותו, או להזכיר בהדפסה.

---

## 2. מסד נתונים וליבה

### `src/database.py`
- **עושה:** מגדיר את כל המודלים (TenantModel, ClientModel, ReportRunModel, WebhookModel, AlertSentModel, UserModel, ApiKeyModel, VulnerabilityModel, SystemAuditLogModel, AttackSurfaceSnapshotModel, MonitoredSourceModel). מנוע: PostgreSQL (async + sync) או SQLite (NullPool, WAL, busy_timeout). ל־PostgreSQL: pool 500, max_overflow 1000, pool_pre_ping. פונקציות: `get_engine`, `get_async_engine`, `get_session_factory`, `get_db`, `get_async_session`, `init_db`. ב־init_db: יצירת טבלאות + ALTER TABLE ל־SQLite (הוספת עמודות כמו tenant_id, secret, pdf_path, sso_provider, sso_id, proof, auto_detect_tech_stack).
- **איך:** SQLAlchemy 2.x, declarative_base, NullPool ל־SQLite, event listener ל־PRAGMA.
- **חסר:** אין Alembic migrations מנוהלות כשעובדים עם PostgreSQL (יש תיקיית alembic אבל הזרימה העיקרית היא init_db + ALTER ידני ל־SQLite).
- **עבודה נדרשת:** להבטיח שכל שינוי סכמה עתידי ייכתב כ־migration ב־Alembic ל־production; ל־SQLite להמשיך ALTER בתוך init_db.

---

## 3. Celery ומשימות רקע

### `src/celery_app.py`
- **עושה:** הגדרת Celery עם Redis כ־broker ו־backend. task_routes: run_scan, run_scan_single_client → scan; run_parallel_scan_dispatcher, clear_scanning_flag, schedule_next_scan_cycle → orchestrator; run_fuzz → fuzz; שאר המשימות → orchestrator. Beat: orchestrator_cycle כל 300s, auto_check כל 300s, discovery כל 12h, supply_chain כל 24h, darkweb כל 1h, github-events כל 300s, github-profile כל 600s.
- **איך:** `app.conf.update(...)`, `beat_schedule={...}`.
- **חסר:** אין תור נפרד ל־PDF (כל ה־PDF נוצר מתוך משימות scan/orchestrator). אין retry policy מפורשת לכל המשימות.
- **עבודה נדרשת:** אופציונלי: תור `pdf` ו־retry ל־generate_report_pdf במקרה של כשל.

### `src/celery_tasks.py`
- **עושה:**
  - **run_scan_single_client_task(client_id):** טוען לקוח, מריץ fingerprint (URLs + IP ranges), מעדכן `client.tech_stack` ב־DB, מריץ קורלציה ללקוח בודד, יוצר ReportRun אחד, מסנכרן ל־vulnerabilities, מייצר PDF (generate_report_pdf_auto), מריץ fuzzer על הדומיין הראשון. כל הלקוחות רצים במקביל דרך group.
  - **schedule_next_scan_cycle_task:** chord callback — בודק אם `weissman:scanning_active` ב־Redis; אם כן, מתזמן את הדיספצ'ר שוב אחרי `SCAN_CYCLE_DELAY_SECONDS` (ברירת מחדל 3600).
  - **run_parallel_scan_dispatcher_task(tenant_id):** מביא את כל הלקוחות (לפי tenant_id אם נתון), מגדיר Redis scanning_active=1 ו־scanning_clients_count, מריץ chord: group של run_scan_single_client_task לכל client_id, ואז schedule_next_scan_cycle_task.
  - **run_scan_task(client_ids):** סריקה "קלאסית" — כל הלקוחות ב־run אחד, קורלציה אחת, ReportRun אחד, PDF אחד, ו־fuzzer לכל לקוח. משמש ל־API ו־/run הישן.
  - **run_orchestrator_cycle_task:** קורא ל־jobs.orchestrator_cycle() ומתזמן את עצמו שוב אחרי 300s.
  - **run_auto_check_task, run_discovery_task, וכו':** קוראים ל־jobs המקבילים.
  - **generate_report_pdf_task:** Celery wrapper ל־PDF.
- **איך:** group, chord, get_session_factory, correlation, fingerprint, pdf_export, jobs.
- **חסר:** ב־run_scan_single_client_task אין עדכון ל־ReportRunModel.tenant_id אם client.tenant_id הוא None (מטופל חלקית). אין שמירת proof מ־fuzzer ל־VulnerabilityModel מתוך המשימה הזו — ה־proof מגיע דרך internal_fuzzer_report_created.
- **עבודה נדרשת:** לוודא שכל run נשמר עם tenant_id נכון; לוודא ש־proof מ־fuzzer שמסיים בתוך המשימה מתעדכן ב־vulnerabilities אם יש מנגנון כזה.

---

## 4. Jobs ולוגיקת רקע

### `src/jobs.py`
- **עושה:**
  - **_sync_run_findings_to_vulnerabilities:** ממלא את טבלת vulnerabilities לפי findings_serializable אחרי יצירת ReportRun.
  - **auto_check_job:** מביא לקוחות, קורלציה, דילוג אם אין ממצאים; בודק delta (CVE השתנו?) — רק אם יש שינוי שומר דוח, מסנכרן vulnerabilities, שולח PDF, webhooks, והתראות Telegram ל־High/Critical, ועדכון delta snapshot.
  - **discovery_job:** לכל לקוח — run_full_recon (subdomains, buckets, וכו'), שולח discovery alerts על נכסים חדשים, מעדכן snapshot.
  - **supply_chain_secret_job:** run_supply_chain_scan + run_secret_scan לכל לקוח.
  - **autonomous_recon_fuzz_job:** fingerprint ואז fuzzer עם tech_stack; קורא ל־run_fuzzer_binary עם notify_url.
  - **exploit_matching_job:** שולף ריפו exploit גלובלי (search_global_exploit_repos), לכל לקוח — filter_matching_exploits, safe_probe, send_exploit_alert_if_new; בנוסף חיפוש per-client (fetch_exploit_repos_for_tech_stack).
  - **orchestrator_cycle:** לכל לקוח — Dark Web scan; אם ממצא — Telegram + Fuzzer; אז auto_check_job, autonomous_recon_fuzz_job, exploit_matching_job.
- **איך:** get_session_factory, correlation, delta_scan, recon_engine, darkweb_intel, alerts, fingerprint, threat_intel, exploit_matcher, webhooks, supply_chain, secret_scan.
- **חסר:** ב־orchestrator_cycle אין שימוש ב־run_parallel_scan_dispatcher — הלולאה הרציפה (autopilot) מונעת רק מ־Dashboard (Start Continuous Scanning) שמפעיל את הדיספצ'ר; Beat מפעיל orchestrator_cycle ו־auto_check בנפרד. כלומר יש שני "מנועים": autopilot (dispatcher + chord) ו־beat (orchestrator_cycle כל 5 דקות).
- **עבודה נדרשת:** להחליט אם autopilot אמור להחליף את orchestrator_cycle או להשלים אותו; לתעד את ההבדל בין "סריקה רציפה" ל־"מחזור אורקסטרציה כל 5 דקות".

---

## 5. קורלציה ו־Feeds

### `src/correlation.py`
- **עושה:** `correlate_findings_to_clients(config_path)` — קורא config.yaml, מריץ feeds (NVD, GitHub, OSV, OTX), HIBP per-domain, ומתאים ממצאים ל־tech_stack של כל client. `correlate_findings_from_db(db_clients)` — אותו דבר אבל עם רשימת clients מה־DB; לכל client מריץ גם fingerprint (URLs + IP ranges) וממזג תוצאות ל־tech_stack לפני ההתאמה. `dedupe_by_finding_id` — מחזיר ממצא אחד לכל (client_id, finding_id).
- **איך:** NVDFeed, GitHubFeed, OSVFeed, OTXFeed, HIBPFeed; fingerprint_urls, fingerprint_ip_ranges, merge_fingerprint_into_scope; matches_tech_stack על Finding.
- **חסר:** אין cache ל־feeds — כל קריאה מושכת מחדש מ־NVD/GitHub/OSV/OTX. עלול להאט ולהיתקע ב־rate limit.
- **עבודה נדרשת:** cache קצר טווח (למשל דקות בודדות) ל־feed results; או להפחית תדירות הקריאות.

### `src/feeds/` (nvd, github, osv, otx, hibp, base)
- **עושות:** NVD — 30 יום אחרונים, עד 200 תוצאות, CVSS → Severity. GitHub — advisories, עד 50. OSV — CSV של modified_id או query API. OTX — pulses (עד 30). HIBP — breacheddomain per domain. כולם משתמשים ב־http_client (timeout, retry).
- **חסר:** OSV ו־GitHub לא תמיד מחזירים CVSS; חלק מהממצאים עלולים להיות בלי severity מדויק. אין pagination מלא ל־NVD (200 מקס).
- **עבודה נדרשת:** תמיכה ב־pagination ל־NVD אם רוצים יותר מ־200 CVE; מילוי severity סביר גם כש־CVSS חסר.

---

## 6. Fingerprint, Fuzzer, ו־Rust

### `src/fingerprint.py`
- **עושה:** `fingerprint_urls(urls)` — קורא לבינארי fingerprint_engine עם רשימת URLs, מחזיר dict url → [tech]. `fingerprint_ip_ranges(ip_ranges, deep)` — קורא `fingerprint_engine ips [cidrs]` (או עם --deep ל־top 1000 פורטים). `run_fuzzer_binary(target_url, ...)` — מפעיל `fingerprint_engine fuzz <url>` ב־Popen עם NOTIFY_URL ו־אופציונלי FUZZ_PAYLOADS_FILE (מ־agent_redteam.write_fuzzer_payloads_file). `merge_fingerprint_into_scope` — ממזג טכנולוגיות מזוהות ל־tech_stack. `run_safe_probe` — קורא ל־safe-probe ב־Rust.
- **איך:** subprocess.run / Popen, timeout 15s ל־fingerprint, parsing JSON מ־stdout.
- **חסר:** אם הבינארי לא קיים — מחזיר {} / False בלי לוג ברור. אין fallback ל־fingerprint בצד Python (רק Rust).
- **עבודה נדרשת:** לוג warning כשהבינארי חסר; אופציונלי: fallback פשוט (למשל רק headers) ב־Python.

### `fingerprint_engine/` (Rust)
- **main.rs:** CLI: `fingerprint_engine <urls>`, `fuzz <url> [payload]`, `ips <cidrs> [--deep]`, `subdomains <domain> [--wordlist]`, `safe-probe <url> [tech_hint]`. מדפיס JSON (או מערך ל־subdomains).
- **lib.rs:** מייצא fingerprint, fuzzer, recon, reporter, validator, safe_probe.
- **fingerprint.rs:** סריקת URLs (headers: Server, X-Powered-By; meta generator), סריקת IP ranges (פורטים 80, 443, 8080 או top 1000 עם --deep), concurrency עם tokio.
- **fuzzer.rs:** baseline request, מוטציות (bit flip, dangerous chars, length), השוואה ל־baseline (זמן, status, content-length); אם אנומליה — קורא ל־reporter.
- **reporter.rs:** יוצר קובץ Markdown בדוח (target, payload, anomaly_type, baseline vs anomaly, curl PoC) ב־reports/; ללא API חיצוני.
- **validator.rs:** אימות אנומליה עם סט payloads משני.
- **recon.rs:** enum subdomains (wordlist או default), concurrency.
- **safe_probe.rs:** בדיקה לא הרסנית (headers, timing).
- **ממומש:** ב־reporter.rs — אחרי כתיבת הקובץ ל־reports/, אם קיים env NOTIFY_URL נעשה POST עם ה־filename; Python מעביר NOTIFY_URL כ־http://127.0.0.1:PORT/internal/fuzzer-report-created ולכן דוח חדש מגיע ל־app.py ומוזן ל־vulnerabilities + Telegram.
- **חסר:** אין retry ב־Rust אם ה־POST נכשל (למשל Python לא רץ או חסום).
- **עבודה נדרשת:** אופציונלי: retry ל־NOTIFY ב־Rust; או תיעוד שהשרת חייב להיות זמין כדי לקבל את הדוח.

---

## 7. Web (FastAPI) — `src/web/app.py`

- **עושה:** FastAPI עם lifespan (init_db, ensure_user_exists, Redis PubSub ל־Command Center WebSocket). Mount ל־/static, router ל־/api/v1. Middleware: דורש login ל־/command-center. Routes: login (כולל SSO, MFA), logout, dashboard (עם scan_status מ־Redis), /api/scan/status, /api/scan/start, /api/scan/stop, /run (סריקה סינכרונית אחת — כל הלקוחות ב־run אחד), /clients (CRUD), /reports, /reports/{id}, report PDF download, webhooks, fuzzer-reports, /internal/fuzzer-report-created (פרסור דוח MD ויצירת run + vulnerability עם proof), PUT /api/findings/{id}/status, GET /api/export/findings (CSV), Command Center (הגשה של frontend/dist). Parsing של דוח fuzzer (target_url, anomaly_type, proof) והזרקה ל־vulnerabilities.
- **איך:** Jinja2Templates, require_role, get_tenant_id, log_action, correlation, validate_findings, pdf_export, webhooks, alerts.
- **חסר:** ה־/run הישן רץ סינכרוני — על הרבה לקוחות יכול להיתקע. אין rate limit על /run. ה־CSV export מוגבל ל־10,000 שורות.
- **עבודה נדרשת:** להפנות /run ל־run_parallel_scan_dispatcher (או להסיר ולהשאיר רק "Start Continuous Scanning"); להוסיף rate limit על טריגר סריקה אם נדרש.

---

## 8. דשבורד ו־UI (תבניות)

- **dashboard.html:** כרטיסים (clients, last run, security score), כפתור "Start Continuous Scanning" / "Stop Scanning" עם fetch ל־/api/scan/start ו־/api/scan/stop, אינדיקציה "Scanning X clients in parallel", Export to CSV.
- **client_form.html:** שם, domains, ip_ranges, tech_stack, צ'קבוקס "Auto-detect Tech Stack" (שדה tech_stack read-only כשמסומן), contact_email. סקריפט שמחליף read-only לפי צ'קבוקס.
- **reports.html, report_detail.html:** רשימת דוחות, לינק ל־PDF, טבלת ממצאים עם dropdown לעדכון status (PUT /api/findings/{id}/status).
- **login.html, login_mfa.html, login_mfa_setup.html:** התחברות, MFA, SSO (לינק ל־/auth/login/sso).
- **webhooks.html:** ניהול webhooks.
- **base.html:** שלד ניווט.
- **חסר:** אין polling ל־/api/scan/status — המשתמש must לרענן כדי לראות "Scanning X" מתעדכן. אין הודעת "Next scan in X minutes" כשהסיבוב הסתיים והבא מתוזמן.
- **עבודה נדרשת:** רענון אוטומטי קל ל־scan_status כל 10–30 שניות בדשבורד; או להציג "Next cycle in ~X min" אם יש מידע כזה ב־Redis.

---

## 9. API ציבורי

### `src/api_public.py`
- **עושה:** GET /api/v1/findings — רשימת vulnerabilities עם pagination ו־filter לפי status; X-API-Key חובה (verify_api_key). POST /api/v1/scans/trigger — body עם client_ids (אופציונלי); קורא run_scan_task.delay(client_ids) או run_parallel_scan_dispatcher_task.delay(); אחרי הסריקה לא מחכה לתוצאה — מחזיר מיד.
- **איך:** ApiKeyModel (key_hash, key_prefix), hashlib.sha256; אם Redis חסר — רץ סינכרוני.
- **חסר:** אין webhook או callback כשהסריקה מסתיימת; הלקוח חייב ל� polling ל־/findings. אין rate limit per API key.
- **עבודה נדרשת:** אופציונלי: webhook בסיום סריקה; rate limit per key.

---

## 10. מודיעין איומים, Dark Web, Exploit

### `src/threat_intel.py`
- **עושה:** חיפוש GitHub (exploit, poc, payload, cve, vuln + tech_stack), fetch_exploit_repos_for_tech_stack, search_global_exploit_repos; תיאור קונטקסטואלי ל־PDF (איך הכלי רלוונטי ל־tech של הלקוח).
- **איך:** GitHub API, http_client.
- **חסר:** תלות ב־GITHUB_TOKEN; ללא token המגבלות נמוכות. אין cache — כל קריאה ל־API.
- **עבודה נדרשת:** cache קצר; fallback כש־token חסר.

### `src/darkweb_intel.py`
- **עושה:** כל הבקשות דרך Tor (socks5h://127.0.0.1:9050). חיפוש דומיינים, tech stack, שמות חברות במקורות (ahmia, onion.live, וכו'). Tor-Killswitch: אם הבדיקה ל־check.torproject.org נכשלת — מפסיקים. run_darkweb_scan(domains, tech_stack, company_names) — מחזיר findings.
- **איך:** requests עם proxies=TOR_PROXY, get_with_retry, regex ל־.onion.
- **חסר:** Pastebin/Telegram/XSS.is מוזכרים במסמכים אבל המקורות בפועל מוגבלים; DORK_QUERIES ו־LEAK_INDICATORS משמשים אבל לא כל המקורות ממומשים.
- **עבודה נדרשת:** להרחיב מקורות (Pastebin, וכו') אם רלוונטי; לוודא ש־Tor-Killswitch מופעל בכל נתיב.

### `src/exploit_matcher.py`
- **עושה:** משווה ריפו exploit ל־tech_stack של הלקוח (filter_matching_exploits).
- **חסר:** תלוי ב־threat_intel ו־fingerprint; אין גרסה/גרסאות — רק שם טכנולוגיה.
- **עבודה נדרשת:** התאמה גם לפי גרסה אם זמינה.

---

## 11. PDF, Webhooks, Alerts

### `src/pdf_export.py`
- **עושה:** ייצוא PDF (WeasyPrint): כריכה, ציון אבטחה, סיכום, טבלת ממצאים, reproduction curl דינמי (ללא placeholders), סעיף multi-language (Bash, Python, JS, Go), Global Threat Intelligence עם תיאור קונטקסטואלי, חותמת SHA-256. generate_report_pdf, generate_report_pdf_auto — שמירה ב־reports/ עם שם CompanyName_VulnID_Timestamp.
- **איך:** HTML → WeasyPrint, client_targets ל־curl אמיתי, proof ממיזוג מ־vulnerabilities.
- **חסר:** תלות ב־WeasyPrint (התקנה ו־dependencies); על מערכות מסוימות דורש התקנות נוספות.
- **עבודה נדרשת:** תיעוד דרישות מערכת ל־PDF; fallback ל־HTML אם WeasyPrint חסר.

### `src/webhooks.py`
- **עושה:** build_webhook_payload (report_id, timestamp, summary, findings), push_findings_to_webhooks — POST ל־כל webhook מופעל עם X-Weissman-Signature (HMAC-SHA256).
- **איך:** WebhookModel, secret per webhook, requests.
- **חסר:** אין retry על כשל; אין אימות שהלקוח קיבל (אין callback).
- **עבודה נדרשת:** retry עם backoff; אופציונלי: סימון "delivered" ב־DB.

### `src/alerts.py`
- **עושה:** send_telegram_alert; דדופ לפי (target, finding_id) ב־24 שעות (AlertSentModel); format_cve_alert, send_cve_alert_if_new, send_fuzzer_alert_if_new, send_darkweb_alert_if_new, send_discovery_alert_if_new, send_exploit_alert_if_new.
- **איך:** TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, safe_post, _record_alert_sent.
- **חסר:** רק Telegram; אין אימייל או Slack.
- **עבודה נדרשת:** אופציונלי: ערוצים נוספים (אימייל, Slack).

---

## 12. מודולים נוספים (קצר)

- **auth_enterprise.py:** RBAC (super_admin, security_analyst, viewer), verify_password, get_user_by_email, ensure_user_exists.
- **web/auth.py:** cookies, session, MFA pending, require_auth, require_role, get_client_ip.
- **web/tenant.py:** get_tenant_id (מה� session / header).
- **audit.py:** log_action → SystemAuditLogModel.
- **region_manager.py:** get_current_region (WEISSMAN_REGION), should_process_tenant.
- **delta_scan.py:** has_changed, save_snapshot (ports, headers, cve_ids, assets) — להתראות רק על שינוי.
- **recon_engine.py:** run_full_recon (CT, DNS, WHOIS, buckets), get_new_assets_for_discovery_alert.
- **supply_chain.py, secret_scan.py:** סריקת NPM/PyPI, typosquatting, חיפוש credentials ב־GitHub.
- **finding_validator.py:** validate_findings (אימות לא הרסני).
- **cvss_epss.py:** weissman_priority_score, get_epss_score.
- **remediation.py:** תיקונים לפי טכנולוגיה + IaC.
- **agent_redteam.py:** write_fuzzer_payloads_file (payloads לפי tech).
- **http_client.py:** timeout 5–8s, get_with_retry עם tenacity (429, 5xx).
- **events_pub.py:** Redis PubSub ל־Command Center (publish_command_center_event).
- **config.py:** load_config מ־YAML (ל־main.py / CLI).
- **models.py:** Finding, ClientFinding, Severity, FindingType.

---

## 13. Frontend (React) — Command Center

- **App.jsx:** Layout, Header (ניווט), Globe, לוח HUD (SecurityScoreGauge, KillChainVisualizer, AssetHexGrid, CyberRadar, LiveIntelTerminal), EmergencyAlert, BackgroundCycler/CinematicBackground. חיבור WebSocket ל־/ws/command-center; אין polling; אין mock data — רק אירועים מ־Redis.
- **Globe.jsx:** Three.js, גלובוס (particles, קשתות, sprites); אירועים מ־WebSocket בלבד.
- **LiveIntelTerminal.jsx:** רשימת אירועים, virtual scrolling, צבע לפי severity.
- **חסר:** אם אין Redis או שאין אירועים — המסך ריק/שקט; אין הודעת "No events" או "Connecting...". אין polling fallback אם WebSocket נופל.
- **עבודה נדרשת:** הודעת חיבור/אין נתונים; reconnect ל־WebSocket.

---

## 14. סיכום: מה עובד, מה חסר, מה לעשות

### עובד היום
- הפעלה ב־`./start_weissman.sh`: Redis, Celery worker+beat, Rust, API.
- דשבורד: login (כולל SSO/MFA), clients CRUD, Auto-detect Tech Stack, Reports, Export CSV, כפתור "Start/Stop Continuous Scanning".
- סריקה מקבילית: group של משימה per client, fingerprint → עדכון tech_stack → CVE → run + PDF + fuzzer; chord מתזמן סיבוב הבא אחרי שעה אם ה־toggle ON.
- Beat: orchestrator_cycle כל 5 דקות, auto_check, discovery, supply_chain, darkweb, github.
- Feeds: NVD, GitHub, OSV, OTX, HIBP; קורלציה עם tech_stack (כולל fingerprint).
- Dark Web (Tor), Exploit matching, Safe probe, Webhooks, Telegram, PDF עם curl דינמי ו־multi-language.
- API ציבורי: GET /api/v1/findings, POST /api/v1/scans/trigger עם X-API-Key.
- Command Center: WebSocket, גלובוס, טרמינל, ללא סימולציה.

### יודע לעשות אבל לא ממומש / חלקי
- main.py (CLI) לא מחובר ל־DB של הדשבורד — שני ערוצים נפרדים (config.yaml vs DB).
- אין cache ל־feeds ו־GitHub — כל הרצה מושכת מחדש.
- אין polling/רענון אוטומטי ל־scan_status בדשבורד.
- אין retry ל־webhooks; אין rate limit ל־API keys.

### דורש עוד עבודה
1. **תיעוד והחלטה:** להבהרה אם "סריקה רציפה" (autopilot) מחליפה את orchestrator_cycle או משלימה; לתעד ב־README/SPEC.
3. **Cache ל־feeds:** cache קצר (דקות) ל־NVD/GitHub/OSV כדי להפחית rate limit ולזרז.
4. **דשבורד:** רענון אוטומטי ל־scan_status; אופציונלי "Next cycle in X min".
5. **API:** rate limit ל־X-API-Key; אופציונלי webhook בסיום סריקה.
6. **Webhooks:** retry עם backoff על כשל.
7. **Rust:** אופציונלי — retry ל־POST NOTIFY_URL אם השרת לא זמין.

---

*סוף הביקורת. עודכן לפי מצב הקוד הנוכחי.*
