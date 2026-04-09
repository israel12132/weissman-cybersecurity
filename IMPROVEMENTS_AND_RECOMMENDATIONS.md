# רשימת כל השיפורים, ההמלצות והתוספות — מהביקורת המלאה

מסמך זה מרכז **הכל** מהסיכום והביקורת: חסרים, שיפורים מומלצים, ותוספות אפשריות.

---

## 1. שורש הפרויקט

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 1.1 | **run_web.py:** לתרגם את הודעות ההפעלה לאנגלית (אם רוצים UI אחיד). |
| 1.2 | **run_web.py:** להוסיף טעינה מפורשת של `.env` כאן (`load_dotenv()`) כדי להבטיח שהמשתנים טעונים. |
| 1.3 | **main.py:** לחבר את main.py (CLI) ל־DB של הדשבורד — "מקור אמת אחד"; או להפסיק להשתמש ב־config.yaml ולהפנות הכל לדשבורד/Celery. |
| 1.4 | **start_weissman.sh:** אם קיים `start_public.sh` — להציע להריץ גם אותו (tunnel), או להזכיר בהדפסה שהמשתמש יכול להריץ אותו ידנית. |

---

## 2. מסד נתונים וליבה

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 2.1 | **database.py:** להבטיח שכל שינוי סכמה עתידי ייכתב כ־migration ב־Alembic ל־production; ל־SQLite להמשיך ALTER בתוך init_db. |

---

## 3. Celery ומשימות רקע

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 3.1 | **celery_app.py:** תור נפרד ל־PDF (queue `pdf`) ו־retry policy מפורשת ל־generate_report_pdf במקרה של כשל. |
| 3.2 | **celery_tasks.py:** לוודא שכל run נשמר עם tenant_id נכון (כולל כשהלקוח ללא tenant). |
| 3.3 | **celery_tasks.py:** לוודא ש־proof מ־fuzzer שמסיים בתוך המשימה מתעדכן ב־vulnerabilities (אם יש מנגנון כזה). |

---

## 4. Jobs ולוגיקת רקע

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 4.1 | **jobs.py:** להחליט אם autopilot (סריקה רציפה) אמור **להחליף** את orchestrator_cycle או **להשלים** אותו. |
| 4.2 | **jobs.py:** לתעד את ההבדל בין "סריקה רציפה" (מהדשבורד) ל־"מחזור אורקסטרציה כל 5 דקות" (Beat) ב־README או SPEC. |

---

## 5. קורלציה ו־Feeds

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 5.1 | **correlation.py:** cache קצר טווח (למשל דקות בודדות) ל־feed results — להפחית עומס ו־rate limit. |
| 5.2 | **correlation.py:** אופציה להפחית תדירות הקריאות ל־feeds. |
| 5.3 | **feeds (nvd, github, osv):** תמיכה ב־pagination מלא ל־NVD אם רוצים יותר מ־200 CVE. |
| 5.4 | **feeds:** מילוי severity סביר גם כש־CVSS חסר (OSV, GitHub). |

---

## 6. Fingerprint, Fuzzer ו־Rust

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 6.1 | **fingerprint.py:** לוג warning כשהבינארי של fingerprint_engine חסר (במקום להחזיר {} בשקט). |
| 6.2 | **fingerprint.py:** אופציונלי — fallback ל־fingerprint בצד Python (למשל רק headers) אם Rust לא זמין. |
| 6.3 | **Rust reporter.rs:** אופציונלי — retry ל־POST NOTIFY_URL אם השרת לא זמין. |
| 6.4 | **Rust:** תיעוד שהשרת (Python API) חייב להיות זמין כדי לקבל דוח fuzzer. |

---

## 7. Web (FastAPI)

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 7.1 | **app.py:** להפנות את `/run` ל־run_parallel_scan_dispatcher (סריקה מקבילית) — או להסיר את `/run` ולהשאיר רק "Start Continuous Scanning". |
| 7.2 | **app.py:** להוסיף rate limit על טריגר סריקה (למשל על `/run` ו־`/api/scan/start`) אם נדרש. |
| 7.3 | **app.py:** אופציונלי — להעלות את מגבלת ה־CSV export מ־10,000 שורות או לתעד אותה. |

---

## 8. דשבורד ו־UI (תבניות)

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 8.1 | **dashboard.html:** רענון אוטומטי (polling) ל־`/api/scan/status` כל 10–30 שניות — כדי ש־"Scanning X clients" יתעדכן בלי רענון ידני. |
| 8.2 | **dashboard.html:** להציג "Next cycle in ~X min" כשהסיבוב הסתיים והבא מתוזמן (אם יש מידע כזה ב־Redis). |

---

## 9. API ציבורי

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 9.1 | **api_public.py:** rate limit per API key (למשל X בקשות לדקה לכל key). |
| 9.2 | **api_public.py:** אופציונלי — webhook או callback כשהסריקה מסתיימת (כדי שהלקוח לא יצטרך רק polling ל־/findings). |

---

## 10. מודיעין איומים, Dark Web, Exploit

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 10.1 | **threat_intel.py:** cache קצר לחיפוש GitHub — להפחית קריאות API. |
| 10.2 | **threat_intel.py:** fallback כש־GITHUB_TOKEN חסר (התנהגות ברורה, לא קריסה). |
| 10.3 | **darkweb_intel.py:** להרחיב מקורות — Pastebin, Telegram, XSS.is וכו' (לפי המסמכים). |
| 10.4 | **darkweb_intel.py:** לוודא ש־Tor-Killswitch מופעל **בכל** נתיב (כל פונקציה שיוצאת לרשת). |
| 10.5 | **exploit_matcher.py:** התאמה גם לפי **גרסה** (version) אם זמינה — לא רק שם טכנולוגיה. |

---

## 11. PDF, Webhooks, Alerts

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 11.1 | **pdf_export.py:** תיעוד דרישות מערכת ל־PDF (WeasyPrint, dependencies). |
| 11.2 | **pdf_export.py:** fallback ל־HTML או הורדת קובץ HTML אם WeasyPrint חסר או נכשל. |
| 11.3 | **webhooks.py:** retry עם exponential backoff על כשל ב־POST. |
| 11.4 | **webhooks.py:** אופציונלי — סימון "delivered" / "failed" ב־DB לכל webhook. |
| 11.5 | **alerts.py:** אופציונלי — ערוצים נוספים: אימייל, Slack (בנוסף ל־Telegram). |

---

## 12. Frontend (React) — Command Center

| # | שיפור / המלצה / תוספת |
|---|------------------------|
| 12.1 | **App.jsx / LiveIntelTerminal:** הודעת "No events" או "Connecting..." כשאין אירועים או כש־WebSocket מתחבר. |
| 12.2 | **App.jsx:** reconnect אוטומטי ל־WebSocket אם החיבור נופל. |
| 12.3 | **Frontend:** אופציונלי — polling fallback אם WebSocket לא זמין (למשל Redis down). |

---

## 13. סיכום מרכזי (מהביקורת)

| # | נושא | פעולה מומלצת |
|----|------|---------------|
| 13.1 | **מקור אמת** | main.py (CLI) לא מחובר ל־DB — לחבר או לתעד שזה ערוץ נפרד. |
| 13.2 | **Cache feeds** | אין cache — כל הרצה מושכת מחדש; להוסיף cache קצר (דקות). |
| 13.3 | **דשבורד scan_status** | אין רענון אוטומטי — להוסיף polling או "Next cycle in X min". |
| 13.4 | **Webhooks** | אין retry — להוסיף retry עם backoff. |
| 13.5 | **API keys** | אין rate limit — להוסיף rate limit per key. |
| 13.6 | **Autopilot vs Orchestrator** | להחליט ולתעד: האם "סריקה רציפה" מחליפה או משלימה את orchestrator_cycle. |
| 13.7 | **Rust NOTIFY** | אופציונלי — retry ל־POST NOTIFY_URL אם Python לא זמין. |

---

## 14. רשימה אחת — לפי עדיפות (המלצה)

**גבוהה (יציבות ו־UX):**
- 8.1 — רענון אוטומטי ל־scan_status בדשבורד  
- 7.1 — הפניה של /run לסריקה מקבילית או הסרה  
- 4.1, 4.2 — החלטה ותיעוד autopilot vs orchestrator  
- 11.3 — retry ל־webhooks  

**בינונית (ביצועים ואבטחה):**
- 5.1 — cache ל־feeds  
- 9.1 — rate limit ל־API keys  
- 2.1 — Alembic migrations ל־production  
- 6.1 — לוג כש־fingerprint binary חסר  

**נמוכה / אופציונלית:**
- 1.1, 1.2 — run_web הודעות ו־.env  
- 1.3 — חיבור main.py ל־DB  
- 1.4 — start_public.sh בהדפסה  
- 3.1 — תור PDF נפרד  
- 5.3, 5.4 — NVD pagination, severity fallback  
- 6.2 — Python fingerprint fallback  
- 6.3, 6.4 — Rust NOTIFY retry + תיעוד  
- 7.2 — rate limit על סריקה  
- 8.2 — "Next cycle in X min"  
- 9.2 — webhook בסיום סריקה  
- 10.1–10.5 — threat_intel cache, darkweb מקורות, exploit גרסה  
- 11.1, 11.2 — תיעוד PDF, fallback HTML  
- 11.4 — webhook delivered ב־DB  
- 11.5 — אימייל/Slack  
- 12.1–12.3 — Frontend הודעות, reconnect, polling fallback  

---

*כל ההמלצות והשיפורים מהמסמך BOT_FULL_AUDIT.md — ריכוז מלא.*
