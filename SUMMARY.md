# סיכום המערכת – Weissman-cybersecurity

## הפעלת המערכת

**פקודת מאסטר יחידה (מתוך שורש הפרויקט):**

```bash
./start_weissman.sh
```

הסקריפט מפעיל venv, בונה את מנוע Rust אם חסר, מריץ את הבקאנד, ואם קיים `start_public.sh` — גם את ה־tunnel הציבורי. לעצירה: Ctrl+C או `kill` על ה־PID שמוצג.

---

## מה המערכת עושה (בגדול)

פלטפורמת Weissman-cybersecurity להערכת אבטחה: מחוברת למקורות מודיעין חיצוניים, משווה ממצאים (CVE, פרצות, איומים) ל-**scope** של כל לקוח (חברה) שאתה מוסיף, ומציג דוחות רק על מה שרלוונטי ללקוח. בנוסף יש זיהוי טכנולוגיות פעיל (fingerprinting) ובדיקת API (fuzzer) שמחפשת אנומליות.

---

## מאיזה כתובות/מקורות הבוט לוקח נתונים

| מקור | כתובת API | מה נמשך | מפתח נדרש |
|------|------------|----------|------------|
| **NVD** (CVE רשמי) | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE מ־30 הימים האחרונים (עד 200 תוצאות) | אופציונלי: `NVD_API_KEY` ב־`.env` |
| **GitHub Security Advisories** | `https://api.github.com/advisories` | עד 50 advisory אחרונים (ממוינים לפי עדכון) | `GITHUB_TOKEN` ב־`.env` |
| **OSV** | `https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv` + `https://api.osv.dev/v1/vulns/{id}` | 20 פרצות אחרונות מ־CSV; אם נכשל – fallback ל־`https://api.osv.dev/v1/query` (חבילות לדוגמה) | לא |
| **AlienVault OTX** | `https://otx.alienvault.com/api/v1/pulses/subscribed` | עד 30 pulses שמנויים אליהם | `OTX_API_KEY` ב־`.env` |
| **Have I Been Pwned** | `https://haveibeenpwned.com/api/v3/breacheddomain/{domain}` | בדיקה **לכל דומיין** של הלקוח (עד 10 דומיינים ללקוח) – האם הדומיין הופיע בדליפה | `HIBP_API_KEY` ב־`.env` |

**הערה:** באפליקציית הווב (דשבורד) משתמשים רק ב־`.env`. קובץ `config.yaml` משמש את הרצה משורת הפקודה (`main.py` / `scheduler`).

---

## איך הבוט עובד (צעד אחר צעד)

1. **טעינת לקוחות**  
   מהמסד (SQLite) או מ־`config.yaml`: לכל לקוח יש שם, **דומיינים**, **טווחי IP** (רק שמירה), **tech stack** (רשימת טכנולוגיות).

2. **משיכת ממצאים**  
   הבוט קורא מכל המקורות למעלה (NVD, GitHub, OSV, OTX) ומאחד רשימת ממצאים (CVE, advisory, threat intel).

3. **Fingerprinting (אופציונלי)**  
   אם יש דומיינים ללקוח – מופעל מנוע Rust שמבצע **בקשות HTTP** לכתובות (עד 15 דומיינים). מכל תגובה הוא מפיק:
   - כותרות: `Server`, `X-Powered-By`
   - ב־HTML: `<meta name="generator" content="...">`  
   הטכנולוגיות שמתגלות (nginx, PHP, WordPress וכו') מתווספות ל־tech stack של הלקוח **לאותה הרצה**. (אם מנוע ה־Rust לא בנוי/לא זמין – הדילוג על fingerprint.)

4. **התאמה ל־scope (קורלציה)**  
   - **Tech stack:** כל ממצא (CVE, advisory וכו') מושווה ל־tech stack של הלקוח (כולל מה שה־fingerprint גילה). אם יש התאמה (למשל CVE על nginx ולקוח עם nginx) – הממצא נכנס לדוח של אותו לקוח.  
   - **HIBP:** נבדק רק עבור **דומיינים** של הלקוח; אם הדומיין מופיע בדליפה – נוסף ממצא מסוג "breach".

5. **דוחות**  
   ממצאים שמתאימים ללקוח נשמרים כדוח (במסד) עם סיכום (כמות לפי חומרה ולפי לקוח). בדשבורד מוצגים בדף "דוחות".

6. **בדיקה אוטומטית כל 5 דקות**  
   כל 5 דקות רץ ברקע אותו תהליך (משיכת feeds → fingerprinting → קורלציה). **דוח חדש נשמר רק אם יש לפחות ממצא אחד**; אם אין ממצאים – לא נוצר דוח.

7. **Fuzzer (בעת "הרץ בדיקה" + אוטומטית כל 12 שעות)**  
   לכל לקוח מריצים fuzzer על הדומיין הראשון. אם מתגלה אנומליה – נשמר דוח ב־`reports/` והמערכת שולחת **התראת Telegram** ("🚨 New Zero-Day Potential Report Generated: [filename]").

8. **התראות Telegram**  
   כשנמצא ממצא **High/Critical** (CVE/advisory) – נשלחת הודעה ל־Telegram עם Target, Severity, Title, Description. כשהפוזר יוצר דוח אנומליה – נשלחת הודעה עם שם הקובץ. נדרש ב־`.env`: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`.

9. **לולאת Recon + Fuzzer אוטונומית (כל 12 שעות)**  
   בלי התערבות: רץ fingerprint על דומיינים ו־**טווחי IP** של כל לקוח, ואז fuzzer על הדומיין הראשון. הפוזר מקבל `NOTIFY_URL` כדי להודיע ל־Python כשיש דוח חדש (ואז נשלחת התראת Telegram).

10. **סריקת טווחי IP (Rust)**  
    טווחי IP (CIDR) מנוצלים: מנוע ה־Rust סורק פורטים 80, 443, 8080 על כל כתובת בטווח (עד 256 כתובות ל־CIDR), ומריץ fingerprinting על שירותים פתוחים. התוצאות ממוזגות ל־tech stack בקורלציה.

11. **Exploit Intelligence & Validation**  
    - **Exploit Scraper** (`threat_intel.py`): סורק GitHub אחר ריפו עם מילות מפתח (exploit, poc, payload, cve, vuln) משולבות עם שמות ה־tech stack. **ללא סינון תאריך** – ריפו מ־2010–2020 נכללים.  
    - **Tool-to-target** (`exploit_matcher.py`): משווה דרישות הריפו ל־fingerprint של הלקוח.  
    - **Safe Probe (Rust)**: בודק שינויי headers ו־timing **בלי payload הרסני**.  
    - לולאה אוטומטית: שליפת ריפו exploit, התאמה, safe-probe, והתראת Telegram.

12. **Dark Web Intelligence** (`darkweb_intel.py`)  
    - כל הבקשות עוברות דרך **Tor**: `socks5h://127.0.0.1:9050`.  
    - חיפוש: דומיינים של הלקוח ב־database dumps, אזכור tech stack בפורומים של exploit, ושמות חברות (כולל Tesla) באתרי דליפה (DLS).  
    - מקורות ניתנים להגדרה ב־`DARKWEB_SOURCES` (ברירת מחדל: מנועי חיפוש שמאנדקסים .onion).  
    - **עמידות בשגיאות**: אם ה־proxy נופל או אתר עושה timeout – לוג והמשך למקור הבא; הבוט לא קורס.

13. **לולאת אורקסטרציה אינסופית (Unlimited scanning)**  
    - במקום interval של 12/6 שעות: **while True** עם jitter מינימלי (0.5 שניות) בין מחזורים.  
    - בכל מחזור: סריקת Dark Web לכל הלקוחות → אם נמצא ממצא: **התראת Telegram** ("🌑 DARK WEB ALERT: Potential threat/leak detected for [Target]... System is now shifting all resources to verify impact.") והפעלת **Fuzzer** (Zero-Day Hunter) על הדומיין הראשון של הלקוח.  
    - אחר כך: CVE check, recon+fuzz, exploit matching.  
    - הבוט רץ עד **עצירה ידנית** של התהליך.

14. **Validator (Rust)**  
    - כשהפוזר מזהה אנומליה (HTTP 500 או Time Anomaly), **Validator** מריץ סט משני של payloads (שונה מהמוטציות של הפוזר) לאימות שהקריסה עקבית ולא תקלה ברשת. רק אם לפחות 2 מתוך הסט המשני מחזירים את אותה אנומליה – נוצר דוח (reporter).

15. **דוח PDF פורמלי (Enterprise)**  
    - בעמוד דוח CVE: כפתור **Export PDF**.  
    - הדוח כולל **Risk Score (CVSS)** 1–10 (מחושב לפי סוג האנומליה/חומרה) ו-**Remediation** (המלצת תיקון).  
    - נוצר עם WeasyPrint ונשמר ב־`data/reports_pdf/`.

16. **Webhooks (Security Platform)**  
    - בדשבורד: **Webhooks** – הגדרת כתובות URL לקבלת ממצאים ב־JSON.  
    - בכל שמירת דוח (הרצה ידנית או אוטומטית) המערכת שולחת **POST** עם payload מובנה (report_id, timestamp, summary, findings עם title, description, severity, cvss_score, remediation) – תואם ל־Jira/Splunk.

---

## מה הבוט כן עושה

- מושך CVE מ־NVD (30 יום אחרונים).  
- מושך GitHub Security Advisories (עם `GITHUB_TOKEN`).  
- מושך פרצות מ־OSV (עדכונים אחרונים או חבילות fallback).  
- אם יש OTX API key – מושך pulses מ־OTX.  
- אם יש HIBP API key – בודק דליפות **רק** עבור דומיינים שמוגדרים ב־scope של כל לקוח.  
- מזהה טכנולוגיות מכתובות (Rust): headers + meta generator.  
- משווה כל ממצא ל־tech stack של הלקוח (כולל alias כמו python/pypi, node/npm).  
- שומר דוחות במסד ומציג בדשבורד (כולל דוח לפי הרצה).  
- רץ אוטומטית כל 5 דקות (כל עוד השרת פעיל) ובודק את **כל** החברות; מעדכן דוחות **רק כשיש ממצאים**.  
- בלחיצה "הרץ בדיקה" – מריץ גם fuzzer על הדומיין הראשון של כל לקוח ושומר דוחות אנומליות ב־`reports/`.  
- גישה באינטרנט דרך Cloudflare Tunnel (`start_public.sh`).  
- התחברות עם אימייל וסיסמה (מ־`.env`: `ADMIN_EMAIL`, `ADMIN_PASSWORD`).

---

## מה הבוט לא עושה (עדיין)

- **סריקת פורטים מלאה** – סורקים רק 80, 443, 8080 (לא סריקת כל הפורטים).  
- **ניטור רציף של שינויים ב־feeds** – הבוט מושך את ה־feeds בכל הרצה (ידנית או כל 5 דקות); אין מנוי או webhook.  
- **דוח PDF/אימייל** – יש תמיכה ב־WeasyPrint ל־PDF ב־`config` אבל בדשבורד הדוחות הם בממשק ווב (ומסד) בלבד.  
- **Reporter עם AI** – דוחות ה־fuzzer נוצרים מתבנית Markdown קבועה (ללא קריאה ל־API חיצוני).

---

## סיכום טכני קצר

| נושא | פרט |
|------|------|
| **שפת ליבה** | Python (FastAPI, SQLAlchemy, feeds).  
| **Fingerprint + Fuzzer + Reporter** | Rust (`fingerprint_engine`).  
| **מסד נתונים** | SQLite (`data/app.db`): לקוחות, הרצות דוחות.  
| **מפתחות** | `.env`: `GITHUB_TOKEN`, `NVD_API_KEY`, `OTX_API_KEY`, `HIBP_API_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`. |
| **תזמון** | כל 5 דקות – קורלציה + שמירת דוח רק אם יש ממצאים. |
| **כתובות חיצוניות** | NVD, GitHub Advisories, OSV (CSV + API), OTX, HIBP – כמתואר בטבלת המקורות למעלה. |

---

## Enterprise One-Click Start

הפעלה במפקד יחיד מתוך שורש הפרויקט:

```bash
./start_weissman.sh
```

**מה הסקריפט עושה:**

1. **הפעלת סביבה וירטואלית** — מפעיל אוטומטית `source venv/bin/activate` או `source .venv/bin/activate` (לפי איזה תיקייה קיימת).
2. **בניית מנוע Rust** — בודק אם הבינארי של `fingerprint_engine` קיים; אם לא, מריץ `cargo build --release` בתיקיית `fingerprint_engine`.
3. **הרצת הבקאנד** — מריץ את שרת ה־Python (`run_web.py`) ברקע.
4. **Tunnel ציבורי (אופציונלי)** — אם קיים הקובץ `start_public.sh`, הסקריפט מפעיל אותו (שרת + Cloudflare Tunnel) במקום להריץ רק את השרת locally; תקבל כתובת HTTPS גלובלית.

**דרישות מוקדמות:**

- תיקיית `venv` או `.venv` עם תלויות מותקנות (`pip install -r requirements.txt`).
- (אופציונלי) Rust מותקן אם רוצים fingerprinting ו־fuzzer; אם הבינארי לא בנוי – הבקאנד יעבוד בלי מנוע ה־Rust.

**עצירה:** כשמריצים רק שרת (בלי `start_public.sh`) — `kill <PID>` או סגירת הטרמינל. כשמריצים עם `start_public.sh` — Ctrl+C בסוף יסיים גם את השרת וגם את ה־tunnel.
