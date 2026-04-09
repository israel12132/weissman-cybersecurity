# Weissman Cybersecurity — מפרט וניתוח הבוט (ניתוח בכיר)

מסמך זה מתאר את מבנה הבוט, סדר הפעולות של המנועים, תפקיד כל מנוע, ומה נדרש לשיפור כדי להגיע לרמת אבטחת לקוח מקסימלית.

---

## 1. מה הוסר (ניקוי)

- **start_public.sh** — הוסר. הפעיל את השרת Python (run_web.py) + cloudflared. לא בשימוש (100% Rust).
- **start_server.sh** — הוסר. הפעיל רק Python (run_web.py). לא בשימוש.

**הפעלה רשמית:** `./start_weissman.sh` (בניית Rust + frontend במידת הצורך, הרצת `fingerprint_engine serve`).

**הערה:** תיקיית `src/` (Python) ו־`run_web.py` עדיין קיימים — סטack ישן. אם אין שימוש, ניתן למחוק אותם כדי לפנות מקום.

---

## 2. סדר הפעולות — מאפס עד סוף (Pipeline)

### שלב 0 — לפני לולאת הלקוחות
| שלב | רכיב | תיאור |
|-----|------|--------|
| 0.1 | **Zero-Day Radar** | רץ **פעם אחת** על כל נכסי כל הלקוחות (אם ללקוח כלשהו המנוע מופעל). שואב NVD/OSV/RSS, Ollama מסנתז בדיקות HTTP בטוחות, ומריץ נגד ה־URLs של הלקוחות. ממצאים נשמרים ב־vulnerabilities עם source=zero_day_radar. |

### שלב 1 — לכל לקוח: הכנה ו־Discovery
| שלב | רכיב | תיאור |
|-----|------|--------|
| 1.1 | טעינת לקוח | קריאת id, name, domains, client_configs מ־clients. חילוץ enabled_engines ו־roe_mode. |
| 1.2 | **target_list** | רשימת יעדים: הדומיין הראשון מ־domains (או name) כ־https://... |
| 1.3 | **DiscoveryContext** | אובייקט משותף: paths, paths_403, wordlist בסיסי (expanded_path_wordlist). |
| 1.4 | **Spider-Sense Crawl** | discovery_engine::run_spider_crawl על target_list — חילוץ נתיבים מ־HTML/JS (href, src, action, fetch, axios, /api/*, comments). עד 40 דפים ו־20 קבצי JS לבסיס. |
| 1.5 | **Archival** | archival_engine — Wayback Machine (CDX) + AlienVault OTX. היסטוריית URLs לדומיין. מיזוג ל־DiscoveryContext. |
| 1.6 | **AI Path Prediction** | discovery_engine::predict_paths_ollama — Ollama מחזיר עד 100 נתיבים צפויים (למשל אם יש /api/v1/auth אז /api/v1/admin וכו'). מיזוג ל־discovery_context. |
| 1.7 | **discovered_paths** | רשימת כל הנתיבים לאימות; 403 נשמרים כ־paths_403 (יעד ל־BOLA/Fuzz). |

### שלב 2 — לכל מנוע מופעל (לפי סדר ALL_ENGINES)
המנועים רצים **לפי הסדר** הבא (כל מנוע רק אם enabled אצל הלקוח):

| # | מזהה מנוע | שם תצוגה | תיאור קצר |
|---|-----------|----------|------------|
| 1 | **osint** | OSINT | crt.sh + WHOIS (HackerTarget). חילוץ סאב־דומיינים. כל סאב־דומיין חדש מתווסף ל־target_list ונשלח SSE new_target. |
| 2 | **asm** | ASM | סריקת פורטים (24 פורטים: 80,443,8080,22,21,...), סאב־דומיינים (recon), fingerprint (HTTP + tech stack), Cloud Hunter (S3/Azure, subdomain takeover). פורטים פתוחים → web_bases (http(s) לכל פורט web). נתיבים מ־tech stack wordlist מתמזגים ל־discovery. אחרי ASM — שוב Spider + Archival + AI prediction. |
| 3 | **supply_chain** | Supply Chain | NPM search לפי prefix הדומיין + בדיקת פגיעויות OSV. ממצאים על חבילות פגיעות. |
| 4 | **leak_hunter** | Leak Hunter | בדיקת נתיבים: .git/HEAD, .env, .aws/credentials, config, .htpasswd, וכו'. עד 20 בסיסים. + חיפוש GitHub (אם github_token מוגדר) לדליפות מפתחות. |
| 5 | **bola_idor** | BOLA/IDOR | בדיקות הרשאות על target_list × discovered_paths. זיהוי גישה לא מורשית (IDOR/BOLA). |
| 6 | **ollama_fuzz** | Ollama Fuzz | Ollama מייצר payloads, שליחה ל־target_list × discovered_paths. כל אנומליה (שינוי status, אורך, זמן, reflection) נשמרת. |
| 7 | **semantic_ai_fuzz** | Semantic AI Fuzz | OpenAPI/ספקטיפיקציה → state machine, Ollama מייצר payloads לוגיים. הרצה על הנתיבים. לוג נשמר ב־semantic_fuzz_log. |
| 8 | **microsecond_timing** | Microsecond Timing | התקפות timing (Blind SQLi וכו') על רשימת URLs (עד 80: בסיס × נתיבים). מדידת delta_us, z_score, confidence. |
| 9 | **ai_adversarial_redteam** | AI Adversarial Red Team | Ollama מייצר prompt-injection payloads, שולח ל־endpoint היעד, Ollama שופט אם התשובה מעידה על פגיעות (OWASP LLM01). |

אחרי כל מנוע: ממצאים נכתבים ל־vulnerabilities; progress נשלח ל־SSE; עבור ASM גם גרף (nodes/edges) ל־asm_graph_*.

### שלב 3 — PoE Synthesis (אם יש crash או ממצאים)
| שלב | רכיב | תיאור |
|-----|------|--------|
| 3.1 | **טריגר** | אם client_had_crash (500/timeout/crash/heuristic מ־ollama_fuzz או semantic_ai_fuzz) **או** client_findings_count > 0. |
| 3.2 | **Strategic Analyzer** | אם יש ממצאים — Ollama מקבל סיכום ממצאים ומחזיר "Attack Chain" (שרשור צעדים לניצול). המצורף ל־context של PoE. |
| 3.3 | **PoE Synthesis** | exploit_synthesis_engine: fingerprint ליעד, רשימת payloads (generic + gadget לפי framework). הרצת probes (HTTP או raw TCP). על כל crash/anomaly: Ollama מסנתז PoC (או נשמר raw cURL). ממצאים עם poc_exploit, remediation, patch. נשמרים כ־source=poe_synthesis. |

### שלב 4 — סיום מחזור
| שלב | רכיב | תיאור |
|-----|------|--------|
| 4.1 | **Audit Root Hash** | crypto_engine — חישוב hash על כל שורות vulnerabilities של ה־run_id. נשמר ב־report_runs.audit_root_hash. |
| 4.2 | **report_runs** | עדכון summary (total, run_at, attack_surface_targets, attack_surface_paths). |

---

## 3. פירוט מנועים (מקסימלי)

### OSINT
- **מטרה:** גילוי סאב־דומיינים ומידע ציבורי.
- **מקורות:** crt.sh (תעודות), HackerTarget WHOIS.
- **פלט:** findings עם type/value (subdomain). כל subdomain חדש מתווסף ל־target_list ומשודר ב־SSE (new_target).
- **הגבלות:** timeout 10s; אין rate limiting מובנה ל־crt.sh.

### ASM (Attack Surface Management)
- **מטרה:** מיפוי פורטים פתוחים, סאב־דומיינים, טכנולוגיות, וסיכוני ענן.
- **פורטים:** 24 (80,443,8080,8443,22,21,25,3306,5432,...). ניתן override מ־config.
- **תהליך:** port scan TCP → subdomain enum (recon) → HTTP fingerprint לכל URL → Cloud Hunter (S3/Azure, takeover).
- **פלט:** findings (port, subdomain, tech), graph_nodes/graph_edges ל־Attack Surface Graph.
- **הגבלות:** PORT_TIMEOUT_MS 500; Cloud Hunter תלוי ב־host + subs.

### Supply Chain
- **מטרה:** זיהוי תלויות וחבילות פגיעות.
- **מקורות:** NPM registry (search), OSV API.
- **פלט:** findings על חבילות עם CVE/פגיעות ידועות.
- **הגבלות:** prefix מהדומיין; אין lockfile parsing (רק search).

### Leak Hunter
- **מטרה:** גילוי קבצים רגישים גלויים ו־GitHub leaks.
- **נתיבים:** /.git/HEAD, .env, .aws/credentials, config, .htpasswd, .docker/config.json, .npmrc, .pypirc וכו'.
- **לוגיקה:** GET לכל base+path; looks_like_leak (תוכן נראה כמו סוד).
- **GitHub:** חיפוש לפי דומיין אם github_token ב־system_configs.
- **הגבלות:** עד 20 בסיסים; 12s timeout.

### BOLA/IDOR
- **מטרה:** זיהוי Broken Object Level Authorization / Insecure Direct Object Reference.
- **תהליך:** הרצה על target_list × discovered_paths; השוואת תגובות בין משתמשים/מזהים.
- **פלט:** findings על גישה לא מורשית.

### Ollama Fuzz
- **מטרה:** Fuzzing מבוסס AI על כל ה־URLs והנתיבים.
- **תהליך:** Ollama מייצר payloads; שליחה; כל אנומליה (status, length, time, reflection) נשמרת.
- **פלט:** findings עם תיאור; אם יש 500/timeout/crash/heuristic → מפעיל PoE.

### Semantic AI Fuzz
- **מטרה:** Fuzzing לוגי לפי OpenAPI/state machine.
- **תהליך:** שליפת ספקטיפיקציה, בניית state machine, Ollama מייצר payloads, הרצה.
- **פלט:** findings + reasoning_log (ב־semantic_fuzz_log).

### Microsecond Timing
- **מטרה:** זיהוי Blind SQLi / timing side-channel.
- **תהליך:** מדידת זמני תגובה, חישוב delta_us, z_score, confidence.
- **פלט:** findings עם delta_us, z_score, payload_preview.

### AI Adversarial Red Team
- **מטרה:** OWASP LLM01 — prompt injection על endpoint AI.
- **תהליך:** Ollama מייצר injection payloads, שולח ליעד, Ollama שופט תשובה.
- **פלט:** findings עם injection_vector, judge_explanation.

### Zero-Day Radar
- **מטרה:** התאמת CVE/פגיעות מ־NVD/OSV ל־stack של הלקוח.
- **תהליך:** שליפת feeds, Ollama מסנתז Safe Probe (path, method, headers, expected_regex), הרצה על נכסי הלקוח.
- **פלט:** findings עם cve_id, target_url, probe_path.

### PoE Synthesis
- **מטרה:** הפיכת crash/anomaly ל־Proof of Exploit עם cURL ו־remediation.
- **תהליך:** fingerprint, generic + gadget payloads, probe (HTTP או raw TCP streaming), זיהוי crash (500/timeout/entropy/heuristic). לכל crash: שמירת raw request כ־cURL; Ollama מסנתז PoC/remediation/patch. אם אין PoC מ־Ollama — נשמר ה־raw trigger.
- **פלט:** findings עם poc_exploit, remediation_snippet, generated_patch, forensic (status + response time).

### Strategic Analyzer
- **מטרה:** שרשור ממצאים ל־Attack Chain (צעדים לניצול מלא).
- **תהליך:** Ollama מקבל סיכום ממצאים ומחזיר רשימת צעדים + CHAIN_PAYLOAD/EXECUTION_ORDER.
- **פלט:** טקסט שמצורף ל־context של PoE.

---

## 4. דשבורד ו־UI

- **כניסה:** Login (AuthContext, JWT ב־cookie). ProtectedRoute על כל המסלולים מלבד /login.
- **בסיס:** `/command-center/` — Cockpit (War Room): GlobalNexus (סיידבר), ClientCockpit (טאבים: Overview, Engine Room, Findings), TargetScopePanel.
- **מסלולים נוספים:** legacy (App עם Globe, KillChain, Radar, וכו'), system-core, report/:id, attack-surface-graph/:id, semantic-logic/:id, timing-profiler, ai-arena, zero-day-radar, cicd-matrix/:id, memory-lab/:id.
- **SSE:** `/api/telemetry/stream` — progress לכל מנוע, new_target, finding_created. WarRoomContext מאזין ומעדכן מפה, EKG, overlay של ממצאים.
- **Real-time:** EKG (latency מ־/api/latency-probe), מפת Drone (zoom ל־new_target), קווים לפי פעילות מנועים, Red Team Skull (roe_mode).

---

## 5. מה צריך שיפור — להגיע לאבטחת לקוח מקסימלית

### 5.1 זיהוי ואיכות
- **פחות False Positives:** הוספת שלב אימות (re-verify) לפני שמירת finding: שליחת ה־payload שוב ו־השוואה.
- **חומרת ממצאים:** מיפוי CVSS/EPSS ל־severity אוטומטי; עדכון severity לפי סביבה (prod vs staging).
- **דדופליקציה:** איחוד ממצאים זהים (אותו path + אותה סיבה) לפני הכנסה ל־DB.

### 5.2 כיסוי התקפות
- **SAST/SCA:** אינטגרציה עם כלי סטטי (או lockfile/תלויות) כדי לסמן חבילות פגיעות כבר מקוד.
- **עומק Crawl:** הגבלת עומק ו־scope (בתוך דומיין) כדי לא להציף; תמיכה ב־robots.txt ו־scope ברור.
- **API ספציפי:** תמיכה ב־GraphQL, gRPC, WebSocket כ־targets ל־fuzz ו־timing.
- **Rate limiting / WAF:** זיהוי חסימות ו־backoff; רוטציית User-Agent ו־IP (כשאפשר) כבר חלקית ב־stealth.

### 5.3 PoE ו־Remediation
- **תמיד PoC:** כבר מיושם — raw cURL נשמר אם Ollama לא החזיר PoC.
- **Remediation:** וידוא ש־remediation_snippet ו־generated_patch מגיעים ל־PDF ו־ל־UI בצורה בולטת; קישור ל־CWE/CVE.
- **Attack Chain:** הפיכת ה־Strategic Analyzer לפלט מובנה (לא רק טקסט) ו־הצגה ב־UI כ־"שרשרת התקפה".

### 5.4 ביצועים ואמינות
- **Timeout ו־Retry:** הגדרות per-engine (למשל timing ארוך ל־PoE, קצר ל־port scan); retry על כשלי רשת.
- **עומס:** הגבלת concurrency גלובלית ו־per-client כדי לא להפיל את היעד.
- **איזון עומסים:** הפסקות בין מנועים (כבר חלקית ב־stealth jitter).

### 5.5 סדר וארגון בבוט ובדשבורד
- **מספור מנועים ב־UI:** הצגת סדר הריצה (1–9 + Zero-Day + PoE) ב־Engine Room.
- **סטטוס מחזור:** "מחזור נוכחי: שלב 2/4 — BOLA/IDOR" ב־Cockpit או ב־Toast.
- **לוג מפורט:** קישור מהדשבורד ל־לוגים לפי run_id (אם נשמרים).
- **הגדרות מנוע:** לכל מנוע — timeout, עומק, wordlist — מתוך system_configs או client_configs, עם UI להגדרה.
- **דוח PDF:** כבר ממוקד signal (Proof of Breach filter, Recon summary). לשמור על פורמט אחד (למשל רק Helvetica) ו־page-break אוטומטי.
- **ארכיון Python:** אם לא נדרש — מחיקת `src/`, `run_web.py`, `requirements.txt`, `.venv` להקטנת בלבול ומקום.

---

## 6. סיכום מבנה קבצים (Backend — Rust)

| קובץ | תפקיד |
|------|--------|
| main.rs | כניסה; קריאת env, DB, spawn orchestrator, הרצת serve. |
| lib.rs | גישות לכל המודולים ו־pub use. |
| server.rs | Axum: routes, auth, API clients/findings/config, PDF, SSE, WebSocket, SPA. |
| server_db.rs | מיגרציות, טבלאות, seed. |
| server_orchestrator.rs | לולאת סריקה, סדר מנועים, Zero-Day, Discovery, PoE, Audit Hash. |
| engine_result.rs | EngineResult, graph_nodes/edges. |
| pipeline_context.rs | DiscoveryContext, wordlists, פונקציות עזר מ־findings. |
| *_engine.rs | כל מנוע (osint, asm, supply_chain, leak_hunter, bola_idor, ollama_fuzz, semantic_fuzzer, timing, ai_redteam, threat_intel). |
| discovery_engine.rs | Spider-Sense + predict_paths_ollama. |
| archival_engine.rs | Wayback + OTX. |
| exploit_synthesis_engine.rs | PoE: fingerprint, probes, Ollama, raw cURL. |
| strategic_analyzer.rs | Attack chain via Ollama. |
| stealth_engine.rs | Jitter, headers, client. |
| crypto_engine.rs | Audit root hash, QR, verification URL. |
| pdf_report.rs | דוח PDF ארגוני (גauge, donut, heatmap, remediation roadmap, findings עם proof). |
| cloud_hunter.rs | S3/Azure, subdomain takeover (נקרא מ־ASM). |
| pipeline_engine.rs | CICD/Pipeline analysis (נקרא מ־server ל־endpoint נפרד). |
| payload_sync_worker.rs | סנכרון payloads (ephemeral, וכו') — worker ברקע. |
| fuzzer.rs, recon.rs, signatures.rs, validator.rs, reporter.rs | בשימוש עקיף (fuzzer מ־server; recon מ־asm; signatures/validator/reporter מ־fuzzer). |
| fingerprint.rs | סריקת tech (נקרא מ־ASM). |
| safe_probe.rs | בדיקות בטוחות (נמצא בשימוש ב־threat_intel וכו'). |

---

*מסמך זה משקף את מצב הבוט לאחר הניקוי והניתוח. לעדכונים — לעדכן את הסדר והמנועים כאן בהתאם.*
