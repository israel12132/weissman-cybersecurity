# Weissman-cybersecurity — מפרט מלא וסיכום לרמת הפרט

**סטטוס:** **Enterprise Scale Distributed** — הבוטל DB bottlenecks (NullPool, SQLite WAL), Multi-tenancy עם אכיפת tenant_id בכל שאילתה, תשתית Celery/Redis חובה למשימות כבדות, ו־APT Attribution בדוח PDF.

**מטרה:** שירותים וחברות ענק (כגון טסלה) ירכשו את הפלטפורמה. המסמך מתאר **בדיוק** מה יש, מה חסר, מה הבוט עושה ולא עושה, מאיפה הוא ניזון, וכל הפרמטרים והגבולות.

---

## 1. הפעלת המערכת

| פעולה | פקודה |
|--------|--------|
| **הפעלה (מאסטר)** | `./start_weissman.sh` |
| **עצירה** | Ctrl+C או `kill <PID>` |

הסקריפט: הפעלת venv, בניית מנוע Rust אם חסר, הרצת הבקאנד; אם קיים `start_public.sh` — גם Cloudflare Tunnel.

---

## 2. מה יש לנו בבוט (רשימת רכיבים מלאה)

### 2.1 ליבת Python (Backend)

| רכיב | קובץ | תפקיד |
|------|------|--------|
| **Web App** | `src/web/app.py` | FastAPI, דשבורד, API; ללא scheduler/thread כש־REDIS_URL מוגדר (Celery מטפל) |
| **מסד נתונים** | `src/database.py` | NullPool (ללא QueuePool); SQLite: WAL, synchronous=NORMAL, busy_timeout=30s. מודלים: clients, report_runs (tenant_id), webhooks (tenant_id), users (tenant_id), וכו' |
| **Jobs** | `src/jobs.py` | לוגיקת רקע: auto_check, discovery, supply_chain, orchestrator_cycle — משותף ל־APScheduler (ללא Redis) או Celery |
| **Tenant** | `src/web/tenant.py` | Dependency get_tenant_id — מזריק ומאכף tenant_id בכל בקשת API (בידוד נתונים מלא) |
| **Threat Attribution** | `src/threat_attribution.py` | APT Attribution: מתאם CVE Critical/High ל־Known Threat Actors (Lazarus, Fancy Bear, וכו'); מופיע ב־PDF |
| **Industry Benchmarks** | `src/benchmarks.py` | C-level: השוואת ציון Weissman ל־Finance, Tech, Automotive, Healthcare, Retail; PDF + Command Center |
| **קורלציה** | `src/correlation.py` | משיכת feeds, fingerprinting, התאמה ל־scope, HIBP לדומיינים |
| **מודלים** | `src/models.py` | Finding, ClientFinding, Severity, FindingType |
| **תצורה** | `src/config.py` | YAML (config.yaml) — משמש הרצה מ־CLI; בדשבורד משתמשים ב־.env |
| **Feeds** | `src/feeds/*.py` | NVD, GitHub, OSV, OTX, HIBP |
| **Fingerprint (Python)** | `src/fingerprint.py` | קריאה למנוע Rust, מיזוג tech stack, IP ranges, safe-probe |
| **התראות** | `src/alerts.py` | Telegram (דילוג אם כבר נשלח ב־24h), CVE/Fuzzer/Dark Web/Discovery |
| **Webhooks** | `src/webhooks.py` | POST ל־URL עם HMAC-SHA256 (X-Weissman-Signature) |
| **ייצוא PDF** | `src/pdf_export.py` | WeasyPrint, כריכה, ציון אבטחה, חותמת SHA-256 |
| **Delta-Scan** | `src/delta_scan.py` | שמירת snapshot (פורטים, headers, CVE, assets); התראות רק על שינוי |
| **CVSS/EPSS** | `src/cvss_epss.py` | וקטור CVSS, EPSS מ־FIRST API, Weissman Priority Score |
| **Remediation** | `src/remediation.py` | תבניות תיקון לפי טכנולוגיה (nginx, apache, php, וכו') |
| **אימות Enterprise** | `src/auth_enterprise.py` | RBAC (super_admin, security_analyst, viewer), MFA (TOTP), ensure_user_exists |
| **Audit** | `src/audit.py` | log_action — רישום immutable לכל פעולה |
| **Dark Web** | `src/darkweb_intel.py` | Tor (socks5h://127.0.0.1:9050), חיפוש דומיינים/tech/חברות, Tor-Killswitch |
| **Exploit Intel** | `src/threat_intel.py` | חיפוש GitHub (exploit, poc, payload + tech stack) |
| **Exploit Matcher** | `src/exploit_matcher.py` | התאמת ריפו ל־fingerprint של הלקוח |
| **Recon** | `src/recon_engine.py` | CT, WHOIS, DNS brute (Rust), S3/Azure/GCP; **Enterprise: ללא cap** — RECON_BATCH_SIZE, RECON_MAX_SUBDOMAINS/MAX_BUCKET_CANDIDATES (0=unlimited), עיבוד בבאצ'ים |
| **Remediation** | `src/remediation.py` | תיקוני טקסט + **IaC** (Terraform, Kubernetes YAML, Ansible); get_remediation_iac ל־Critical |
| **Agent Red-Team** | `src/agent_redteam.py` | Next steps + **סטריקט payloads לפי tech** (IIS/dotnet vs Apache/PHP — ללא ערבוב); fingerprint קודם → fuzzer עם payloads מותאמים |
| **IP–Org** | `src/ip_org.py` | RIPE / ipinfo.io — מיפוי IP ל־ASN/ארגון |
| **Agent Red-Team** | `src/agent_redteam.py` | "Next steps" לפי שירות, payloads ל־Fuzzer לפי tech stack |
| **Supply Chain** | `src/supply_chain.py` | NPM, PyPI, typosquatting, OSV לבדיקת חבילות |
| **Secret Scan** | `src/secret_scan.py` | חיפוש GitHub code (API keys, .env, credentials) |
| **HTTP Client** | `src/http_client.py` | timeout 5–8s; tenacity retry על 429/5xx; **סיבוב פרוקסי** (PROXIES_LIST) — stealth מול WAF |
| **Proxy Rotation** | `src/proxy_rotation.py` | טעינת PROXIES_LIST (פסיק) או PROXIES_FILE; get_random_proxy, get_proxies_dict לשימוש ב־requests |
| **Region Manager** | `src/region_manager.py` | **Data sovereignty (GDPR):** WEISSMAN_REGION אקטיבי; get_current_region, get_tenant_region, should_process_tenant; אחסון ו־orchestrator מוגבלים לאזור (EU-West לא נוגע ב־US-East) |
| **Events Pub** | `src/events_pub.py` | Redis PubSub: publish_command_center_event(kind, payload) — audit, critical_cve, darkweb, fuzzer_anomaly, discovery, exploit; WebSocket משדר ל־Command Center בזמן אמת |
| **Celery** | `src/celery_app.py`, `src/celery_tasks.py` | Redis broker חובה ל־Enterprise: run_scan, run_fuzz, run_orchestrator_cycle, run_auto_check, run_discovery, run_supply_chain. Beat: 60s orchestrator, 5min auto_check, 12h discovery, 24h supply_chain. כש־REDIS_URL לא מוגדר — Scheduler + thread in-process (pacing 2–3s) |

### 2.2 מנוע Rust (fingerprint_engine)

| פקודה | תפקיד |
|--------|--------|
| `fingerprint_engine <url1> [url2 ...]` | Fingerprint כתובות — headers, meta generator |
| `fingerprint_engine fuzz <target_url> [base_payload]` | Fuzzer: **context-aware** — כש־FUZZ_PAYLOADS_FILE מוגדר משתמש **רק** ב־payloads מהקובץ (מ־fingerprint); אחרת מוטציות מובנות |
| `fingerprint_engine ips <cidr1> [cidr2 ...]` | סריקת פורטים (80, 443, 8080) + fingerprint על שירותים פתוחים |
| `fingerprint_engine safe-probe <url> <tech_hint>` | בדיקה לא הרסנית (headers, timing) |
| `fingerprint_engine subdomains <domain> [--wordlist path]` | DNS enum (ברירת מחדל 200 concurrency) |

**מודולים:** `fingerprint.rs`, `fuzzer.rs`, `validator.rs`, `reporter.rs`, `safe_probe.rs`, `recon.rs`.

### 2.3 Frontend (Command Center)

| רכיב | תפקיד |
|------|--------|
| **React + Vite + Tailwind** | דף Command Center |
| **Three.js + OrbitControls** | גלובוס הולוגרפי (שכבות: core, wireframe+particles, Fresnel glow), טבעות, קשתות נתונים |
| **SecurityScoreGauge** | ציון 0–100 במעגל (צבע לפי טווח) |
| **LiveIntelTerminal** | טרמינל אנכי מימין — [TIMESTAMP] \| TARGET \| SEVERITY \| ACTION; **Virtual scrolling** (react-window) ל־10,000+ אירועים; **WebSocket** — אין polling, אירועים בזמן אמת מ־Redis PubSub |

### 2.4 תזמון ורקע (Enterprise Scale Distributed)

**כש־REDIS_URL מוגדר:** כל המשימות הכבדות רצות ב־Celery workers; FastAPI נשאר non-blocking. הרצת Beat: `celery -A src.celery_app beat`; Workers: `celery -A src.celery_app worker -Q scan,fuzz,orchestrator`.

| משימה | תדירות | תיאור |
|--------|--------|--------|
| **orchestrator_cycle** | כל 60 שניות (Beat) | Dark Web → אם ממצא: Telegram + Fuzzer; אחר כך auto_check, recon+fuzz, exploit matching |
| **auto_check** | כל 5 דקות (Beat) | Delta CVE + שמירת דוח רק על שינוי; התראות High/Critical |
| **discovery** | כל 12 שעות (Beat) | Recon (subdomains, buckets) + Shadow IT alert |
| **supply_chain_secret** | כל 24 שעות (Beat) | Supply chain + secret scan |

**בלי REDIS_URL:** APScheduler (5min, 12h, 24h) + thread שמריץ orchestrator_cycle עם **dynamic pacing** — שינה 2–3 שניות (עם jitter) בין מחזורים כדי למנוע עומס CPU ו־DB (במקום 0.5s polling).

**HTTP ו־Rate limiting (Enterprise):** כל קריאות HTTP חיצוניות (NVD, GitHub, crt.sh, HackerTarget, Tor, וכו') משתמשות ב־`src/http_client`: **timeout 5–8 שניות** (fail-fast), ו־**tenacity** — retry עם exponential backoff (2s, 4s, 8s) + jitter על 429 (Rate Limit) ו־5xx, ללא קריסה או hammering.

---

## 3. מה אין לנו (חסרים / מגבלות)

- **סריקת פורטים מלאה** — רק 80, 443, 8080 (ו־Rust: רשימת top ports בפנים, לא כל 65535).
- **ניטור feeds בזמן אמת** — אין webhook מהמקורות; רק poll (כל 5 דקות או 60s ב־orchestrator).
- **דוח PDF אוטומטי במייל** — PDF זמין רק דרך כפתור "Export PDF" בדשבורד.
- **Reporter עם AI חיצוני** — דוחות Fuzzer מתבנית Markdown קבועה (ללא Gemini/API).
- **גבולות קשיחים** — ראה סעיף 7 (לימיטים).

**הוסר (הושג):** צוואר הבקבוק של DB (NullPool + SQLite WAL); Multi-tenancy לא מלא (כעת אכיפת tenant_id בכל API ו־query); Celery אופציונלי (כעת כש־REDIS_URL מוגדר — משימות כבדות רק ב־workers); חסר APT Attribution (כעת מודול threat_attribution + סעיף "Likely Threat Actors" ב־PDF).

---

## 4. מה הבוט עושה (תהליכים מפורטים)

1. **טעינת לקוחות** — מהמסד (או מ־config.yaml ב־CLI). לכל לקוח: שם, דומיינים, טווחי IP, tech_stack.
2. **משיכת ממצאים** — NVD (30 יום, עד 200), GitHub (50), OSV (20 או fallback), OTX (30), HIBP **לכל דומיין** (עד 10 דומיינים ללקוח).
3. **Fingerprinting** — כל דומיינים (ללא cap); קריאה ל־Rust; מיזוג Server, X-Powered-By, meta generator ל־tech_stack. **Fuzzer:** תמיד אחרי fingerprint — payloads רק לפי tech שזוהה (IIS vs Apache/PHP).
4. **סריקת IP** — Rust: עד 256 כתובות לכל CIDR; פורטים 80, 443, 8080 (+ רשימת top ports בפנים); fingerprint על פתוחים.
5. **קורלציה** — התאמת כל ממצא ל־tech_stack (כולל alias); HIBP רק לדומיינים ב־scope.
6. **דוחות** — שמירה ב־report_runs; דוח חדש **רק אם יש לפחות ממצא אחד** (וגם Delta: רק אם יש שינוי ב־CVE).
7. **Fuzzer** — "הרץ בדיקה" + אוטומטית כל 12 שעות; דומיין ראשון; Validator מאשר אנומליה; דוח ב־reports/; NOTIFY_URL ל־Python → Telegram.
8. **התראות Telegram** — High/Critical CVE, דוח Fuzzer, Dark Web, Exploit match, Shadow IT; דילוג אם אותו מפתח נשלח ב־24h.
9. **Dark Web** — Tor; חיפוש דומיינים, tech, שמות חברות; Tor-Killswitch; בהתאמה: Fuzzer + Telegram.
10. **Exploit matching** — GitHub exploit/poc + tech stack → התאמה → Safe Probe → Telegram.
11. **Recon** — CT, WHOIS, DNS (Rust), S3/Azure/GCP; **ללא הגבלת 15–20** — באצ'ים (RECON_BATCH_SIZE); Shadow IT → [Weissman-Discovery] Telegram.
12. **Remediation** — טקסט + **IaC** (Terraform, K8s, Ansible) ל־Critical; get_remediation_iac ב־PDF.
13. **Webhooks** — POST עם JSON + X-Weissman-Signature (HMAC-SHA256).
14. **PDF** — כריכה, ציון אבטחה, Executive Summary, **Likely Threat Actors**, Heatmap, CVSS, Remediation + **IaC (DevOps)** ל־Critical, חותמת SHA-256.
15. **RBAC + MFA** — כניסה עם אימייל/סיסמה; חובה MFA (TOTP); תפקידים: super_admin, security_analyst, viewer.
16. **Audit Log** — כל פעולה (login, scan, download, וכו') נשמרת ב־system_audit_logs.
17. **Multi-tenancy** — get_tenant_id מוזרק לכל בקשת API; Client, ReportRun, Webhook מסוננים לפי tenant_id; super_admin רואה הכל.
18. **Distributed scale** — כש־REDIS_URL מוגדר: אין scheduler/thread בתהליך ה־API; Celery workers + Beat מריצים orchestrator_cycle, auto_check, discovery, supply_chain.

---

## 5. מה הבוט לא עושה

- לא סורק את **כל** הפורטים (רק מוגבל).
- לא מקבל עדכונים מ־feeds ב־real-time (רק poll).
- לא שולח דוח PDF אוטומטית במייל.
- לא מריץ payloads הרסניים (Safe Probe ו־Validator לא מבצעים הרס).
- בלי REDIS_URL: רץ ב־single process עם scheduler + thread; עם REDIS_URL: Celery workers מטפלים (מחייב הרצת worker + beat).

---

## 6. מאיזה מקורות הבוט ניזון — ופרמטרים

| מקור | כתובת / endpoint | מה נמשך | לימיט | מפתח (.env) |
|------|-------------------|----------|--------|-------------|
| **NVD** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE מ־30 הימים האחרונים | 200 תוצאות; **5–8s timeout** + retry (tenacity) | `NVD_API_KEY` (אופציונלי) |
| **GitHub Advisories** | `https://api.github.com/advisories` | Advisory מעודכנים | 50; **5–8s timeout** + retry | `GITHUB_TOKEN` (מומלץ) |
| **OSV** | CSV: modified_id (20 אחרונים) + API vulns; fallback: query | פרצות | 20 מ־CSV; 10 ב־fallback; **5–8s timeout** + retry | — |
| **AlienVault OTX** | `https://otx.alienvault.com/api/v1/pulses/subscribed` | Pulses מנויים | 30; **5–8s timeout** + retry | `OTX_API_KEY` |
| **HIBP** | `https://haveibeenpwned.com/api/v3/breacheddomain/{domain}` | דליפות לדומיין | עד 10 דומיינים; **5–8s timeout** + retry | `HIBP_API_KEY` |
| **FIRST (EPSS)** | `https://api.first.org/data/v1/epss?cve=CVE-xxx` | ציון EPSS ל־CVE | לפי CVE; **5–8s timeout** + retry | — |
| **crt.sh** | `https://crt.sh/?q=%25.{domain}&output=json` | subdomains מ־CT | **5–8s timeout** + retry | — |
| **HackerTarget** | hostsearch/?q= | subdomains מ־WHOIS/host | **5–8s timeout** + retry | — |
| **GitHub Search** | search/repositories (exploit, poc, וכו') | ריפו לפי tech | 30 per_page; 5 tech terms; **5–8s timeout** + retry | `GITHUB_TOKEN` |
| **GitHub Code Search** | search/code (secret scan) | קוד רגיש | עד 30 תוצאות; **5–8s timeout** + retry | `GITHUB_TOKEN` |
| **Dark Web** | דרך Tor (127.0.0.1:9050) | דומיינים, tech, שמות חברות | DARKWEB_SOURCES; **5–8s timeout** + retry | — |
| **RIPE / ipinfo** | whois/data.json; ipinfo.io/{ip}/json | ASN/ארגון ל־IP | **5–8s timeout** + retry | — |
| **NPM / PyPI** | registry.npmjs.org; pypi.org | חבילות + typosquat | 15–20 חבילות; **5–8s timeout** + retry | — |

---

## 7. פרמטרים וגבולות (לימיטים מספריים)

| פרמטר | ערך | הערות |
|--------|------|--------|
| **HTTP timeout (כל קריאות חיצוניות)** | **5–8 שניות** | `ENTERPRISE_HTTP_TIMEOUT`; fail-fast, ללא 25–30s |
| **HTTP retry (429 / 5xx)** | **3 ניסיונות** | tenacity: exponential backoff 2s, 4s, 8s + jitter 0–1s |
| **Orchestrator loop (בלי Redis)** | **2–3s שינה** | dynamic pacing עם jitter (לא 0.5s polling) |
| דומיינים ל־fingerprint ללקוח | 15 | `domains[:15]` |
| דומיינים ל־HIBP ללקוח | 10 | `domains[:10]` |
| כתובות IP לכל CIDR (Rust) | 256 | `MAX_IPS_PER_CIDR` |
| פורטים נסרקים (Rust IP scan) | ברירת מחדל: 80, 443, 8080; עם `--deep` או `WEISSMAN_DEEP_SCAN=1`: Top 1000 Nmap | — |
| NVD resultsPerPage | 200 | — |
| GitHub advisories per_page | 50 | — |
| OSV recent | 20 (מ־CSV) | — |
| OTX pulses | 30 | — |
| תוצאות דוח (למשתמש) | 20 (לעמוד) | — |
| Command Center score findings | **ללא cap** | חישוב ציון על כל הממצאים; **pagination** ב־/api/command-center/findings (עד 500 לעמוד) |
| Ticker events | **Pagination** | /api/command-center/ticker?page=1&per_page=500 (עד 2000); **WebSocket** לדחיפה בזמן אמת |
| Audit log (להצגה) | כמו Ticker | pagination; אין cap של 50 |
| Webhook URL length | 2048 | — |
| Secret (webhook) | 512 | — |
| Subdomains / buckets (recon) | **ללא הגבלה** (אופציונלי RECON_MAX_SUBDOMAINS, RECON_MAX_BUCKET_CANDIDATES; 0=unlimited) | עיבוד בבאצ'ים (RECON_BATCH_SIZE=500) |
| Keywords (buckets) | ללא cap | — |
| Supply chain NPM/PyPI | 15–20 | — |
| Secret scan GitHub | 150 max_results (Enterprise); 50 per request | — |
| Threat intel tech terms | 5 | — |
| Dark Web tech/company terms | 10 | — |
| MFA cookie max_age (הגדרה) | 300 שניות | — |
| Session max_age | 86400 (24h) | — |
| PostgreSQL pool_size | 100 | Enterprise: למניעת deadlocks עם 200+ workers |
| PostgreSQL max_overflow | 200 | — |
| Subdomains DNS (Rust) concurrency | 200 | — |

---

## 8. משתני סביבה (.env)

**חובה / מומלץ לדשבורד:**

| משתנה | חובה | תיאור |
|--------|------|--------|
| `ADMIN_EMAIL` | כן | אימייל כניסה (ברירת מחדל: admin@weissman.local) |
| `ADMIN_PASSWORD` | כן | סיסמה (ברירת מחדל: ChangeMe123!) |
| `GITHUB_TOKEN` | מומלץ | GitHub PAT — Advisories + Exploit search + Secret scan; ללא: rate limit נמוך |

**אופציונלי — מודיעין:**

| משתנה | תיאור |
|--------|--------|
| `NVD_API_KEY` | NVD — ללא: 5 req/30s; עם: גבוה יותר |
| `OTX_API_KEY` | AlienVault OTX — pulses |
| `HIBP_API_KEY` | Have I Been Pwned — breacheddomain |

**אופציונלי — התראות:**

| משתנה | תיאור |
|--------|--------|
| `TELEGRAM_BOT_TOKEN` | בוט Telegram |
| `TELEGRAM_CHAT_ID` | צ'אט להתראות |

**אופציונלי — תשתית:**

| משתנה | תיאור |
|--------|--------|
| `PORT` | פורט שרת (ברירת מחדל 8000) |
| `DATABASE_URL` | PostgreSQL (אם ריק — SQLite ב־data/app.db) |
| `SQL_ECHO` | **Production: מאולף ל־False** (config.get_sql_echo); dev: true להדפסת SQL |
| `REDIS_URL` | **חובה ל־Production** — redis://localhost:6379/0; ללא: סריקות רקע לא רצות |
| `SECRET_KEY` | מפתח ל־session; **Production: אזהרה אם ברירת מחדל** (config.get_secret_key) |
| `DARKWEB_SOURCES` | רשימת מקורות Dark Web (מפרידים; ברירת מחדל מנוצל אם ריק) |
| `PROXIES_LIST` | רשימת פרוקסי (מופרדים בפסיק) לסיבוב IP — stealth מול WAF/Cloudflare |
| `PROXIES_FILE` | נתיב לקובץ (שורה אחת לפרוקסי) אם לא PROXIES_LIST |
| `WEISSMAN_ENV` / `PRODUCTION` | production או 1 — מאלץ SQL_ECHO=False ומאמת SECRET_KEY |
| `RECON_BATCH_SIZE` | גודל באץ' ל־recon (ברירת מחדל 500) |
| `RECON_MAX_SUBDOMAINS` | 0 או ריק = ללא הגבלה; מספר למגביל subdomains ל־exposed API check |
| `RECON_MAX_BUCKET_CANDIDATES` | 0 או ריק = ללא הגבלה; מספר מועמדים ל־S3/Azure/GCP |

**מפתחות אופציונליים:** NVD_API_KEY, OTX_API_KEY, HIBP_API_KEY — חסר לא מפיל; feeds מחזירים ריק/הודעת "not set".

**ל־Rust (מועבר דרך Python / סביבה):**

| משתנה | תיאור |
|--------|--------|
| `NOTIFY_URL` | URL ל־POST כש־Fuzzer יוצר דוח (מוגדר אוטומטית ע"י app.py) |
| `FUZZ_PAYLOADS_FILE` | נתיב לקובץ payloads (AI/contextual); מוגדר ע"י agent_redteam |
| `WEISSMAN_REGION` | **Data sovereignty:** EU-West, US-East, וכו'; אחסון report_runs.region; orchestrator מעבד רק tenants שתואמים לאזור; שאילתות דוחות מסוננות לפי region |
| `PROXIES_LIST` / `PROXIES_FILE` | סיבוב פרוקסי גם במנוע Rust (reqwest) |

**דוגמת .env (ללא ערכים רגישים):**

```env
# Copy to .env and fill. Do not commit .env.
GITHUB_TOKEN=
ADMIN_EMAIL=admin@weissman.local
ADMIN_PASSWORD=ChangeMe123!

# Optional
# NVD_API_KEY=
# OTX_API_KEY=
# HIBP_API_KEY=
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
# PORT=8000
# DATABASE_URL=postgresql://user:pass@host/dbname
# REDIS_URL=redis://localhost:6379/0
# SECRET_KEY=your-secret
# DARKWEB_SOURCES=
```

---

## 9. ארכיטקטורה טכנית (קצר)

| שכבת | טכנולוגיה |
|--------|------------|
| **Backend** | Python 3, FastAPI, SQLAlchemy (sync + async ל־PostgreSQL) |
| **DB** | SQLite (ברירת מחדל), PostgreSQL + Alembic (כש־DATABASE_URL) |
| **תזמון** | **Celery + Redis בלבד** — אין APScheduler; FastAPI מטפל רק ב־API; workers מריצים orchestrator, auto_check, discovery, supply_chain, PDF |
| **מנוע סריקה** | Rust (tokio, reqwest) — fingerprint, fuzz, validator, reporter, safe-probe, recon |
| **Frontend** | React, Vite, Tailwind, Three.js |
| **אימות** | Cookie session, RBAC, TOTP (pyotp) |
| **אינטגרציות** | Telegram, Webhooks (HMAC), Tor (requests[socks]) |

---

## 10. התאמה ל־Enterprise (טסלה, ענקיות)

- **יש:** RBAC, MFA, Audit log, Delta alerts, PDF מקצועי, Webhooks עם חתימה, CVSS/EPSS, Remediation, Command Center ויזואלי.
- **C-Level Industry Benchmarking (הושלם):** מודול `src/benchmarks.py` — השוואת ציון Weissman ו־EPSS לממוצעי סקטור. משולב ב־PDF וב־Command Center.
- **Stealth ו־IP Rotation (הושלם):** `PROXIES_LIST` / `PROXIES_FILE` — סיבוב פרוקסי אקראי ב־Python (http_client, proxy_rotation) וב־Rust (fingerprint build_client). מפחית חסימות מ־WAF/Cloudflare.
- **Celery חובה:** אין APScheduler; REDIS_URL נדרש; כל משימות הרקע (כולל יצירת PDF) נשלחות ל־Celery. FastAPI מחזיר רק תגובות מיידיות.
- **אבטחת Production:** SQL_ECHO מאולף ל־False ב־production (config.get_sql_echo); SECRET_KEY מאומת (אזהרה אם ברירת מחדל); מפתחות אופציונליים (OTX, HIBP, NVD) — חסר לא מפיל.
- **Data sovereignty (GDPR):** WEISSMAN_REGION אקטיבי; RegionManager (region_manager.py); tenant.region + report_runs.region; orchestrator ו־API מסננים לפי אזור (תנועת נתונים וסריקה רק באזור המוגדר).
- **WebSockets בזמן אמת:** אין polling ב־Command Center; FastAPI WebSocket `/ws/command-center`; Redis PubSub (weissman:cc:events); Celery/audit/alerts מפרסמים אירועים → broadcast לכל הלקוחות; latency תת־אלפית.
- **Infinite scaling UI:** הסרת cap של 50; pagination ב־ticker (עד 2000 לעמוד) ו־findings (עד 500); Virtual scrolling (react-window) ב־LiveIntelTerminal; דף Reports עם pagination (עד 500 לעמוד).
- **Final Mission Critical — Global Predictive Threat Intel:** (1) **Unlimited scoping:** הסרת מגבלות על tech_terms ו־company_names ב־darkweb_intel ו־recon_engine. (2) **Global monitoring:** `search_global_exploit_repos()` — שליפת כל ה־exploit/PoC/zero-day repos מ־GitHub בלי סינון לפי לקוח; אחר כך **cross-reference** לכל לקוח לפי Tech Stack (exploit_matcher). התאמה → התראת CRITICAL. (3) **PDF — Preemptive Global Threat Intelligence:** סעיף חדש בדוח עם איומים גלובליים (Zero-Days, כלי האקר) שהמערכת התאימה לתשתית הלקוח לפני התקפה. (4) **Infrastructure:** IP rotation פעיל בכל הקריאות החיצוניות (recon_engine, OSV feed משתמשים ב־safe_get); pool_size=100 ל־PostgreSQL; כל משימות הרקע דרך Celery/Redis בלבד.
- **2100 Red-Team HUD:** Command Center עם CSS Grid קפדני; גלובוס חלקיקים (cyan/magenta) במרכז עם OrbitControls וקשתות נתונים; 4 רקעים מתחלפים (Matrix, Hex-Grid, Radar, Dark Dust) כל 120s עם overlay 85%; ברנדינג הולוגרפי למעלה + Global Threat Ticker; פאנלים שמאל (Kill-Chain, Asset Hex-Grid, Score) וימין (Cyber Radar, Live Intel Terminal); WebSockets לעדכונים בזמן אמת.

---

*מסמך זה מעודכן לפי קוד הפרויקט. לפרטים נוספים: SUMMARY.md, AUDIT_ENTERPRISE.md.*
