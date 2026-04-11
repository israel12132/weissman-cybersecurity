# Security Assessment Bot

בוט להערכת אבטחה לחברות: מחובר ל־5 מקורות מודיעין (CVE, GitHub, OSV, OTX, HIBP), מזהה חולשות ופרצות רלוונטיות ללקוח לפי ה־scope שאושר, ומפיק דוחות (כולל דוח שעתי).

## דרישות

- Python 3.10+
- (אופציונלי) Rust + Cargo – לבניית מנוע Fingerprinting פעיל
- הרשאה מפורשת מלקוח לפני כל סריקה/בדיקה על הנכסים שלו

## התקנה

```bash
cd security-assessment-bot
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
# ערוך config.yaml: הוסף לקוחות, scope, ומפתחות API (אופציונלי)

# אופציונלי – מנוע Fingerprinting (Rust) לזיהוי טכנולוגיות מכתובות ה-scope:
cd fingerprint_engine && cargo build --release && cd ..
```

## מקורות מודיעין (5)

| מקור | תיאור | API Key |
|------|--------|---------|
| **NVD** | CVE רשמי (NIST) | אופציונלי – [בקשה כאן](https://nvd.nist.gov/developers/request-an-api-key) |
| **GitHub** | Security Advisories | אופציונלי – GitHub PAT |
| **OSV** | Open Source Vulnerabilities | לא נדרש |
| **AlienVault OTX** | Threat intelligence | [OTX](https://otx.alienvault.com/api) |
| **Have I Been Pwned** | דליפות/דומיינים (רק לדומיינים באישור הלקוח) | [HIBP API](https://haveibeenpwned.com/API/Key) |

## הגדרת לקוחות

ב־`config.yaml` מגדירים לכל לקוח:

- **scope**: דומיינים, טווחי IP (אופציונלי), ו־tech stack (תוכנות/גרסאות) – **רק נכסים שהלקוח הרשה במפורש**.
- הבוט משווה ממצאים ממקורות המודיעין ל־scope ומחזיר רק ממצאים רלוונטיים ללקוח.
- **Tech Stack Fingerprinting (Rust)**: אם בנית את `fingerprint_engine`, בכל הרצת בדיקה הבוט סורק את כתובות ה־scope (HTTP headers + meta generator), מזהה טכנולוגיות (nginx, PHP, WordPress וכו') ומציג בדוח רלוונטיות מדויקת (למשל `Matches tech stack: ['nginx', 'php']`) במקום `['unknown']`.

## שימוש

### הפעלת המערכת (פקודת מאסטר)

```bash
# הפעלה מלאה עם Docker (מומלץ):
./weissman start

# או הפעלה native (ללא Docker):
./weissman start native
```

**פקודות נוספות:**
```bash
./weissman status     # בדיקת סטטוס
./weissman logs -f    # צפייה בלוגים
./weissman stop       # עצירת המערכת
./weissman help       # עזרה מלאה
```

**כתובות:**
- **Command Center:** http://localhost/
- **API:** http://localhost/api/
- **WebSocket:** ws://localhost/ws/

> **הערה:** סקריפט `weissman` מפעיל את כל המערכת כולל PostgreSQL, Backend, Worker ו-Gateway.

- **התחבר** עם שם המשתמש והסיסמה (מוגדרים ב־.env).
- **חברות** – הוסף/ערוך חברות והזן כתובות (דומיינים), טווחי IP ו־Tech Stack.
- **הרץ בדיקה** – מהדשבורד לחץ "הרץ בדיקה עכשיו".
- **דוחות** – צפה בכל ההרצות והממצאים לפי חומרה ולקוח.

מפתחות API למודיעין (אופציונלי) – הגדר כ־environment variables:
`NVD_API_KEY`, `GITHUB_TOKEN`, `OTX_API_KEY`, `HIBP_API_KEY`.

---

### שורת פקודה (ללא ממשק)

- **ריצה חד־פעמית + דוח:**
  ```bash
  python main.py
  ```
- **דוח כל שעה (scheduler):**
  ```bash
  python main.py --hourly
  ```
- **קובץ config מותאם:**
  ```bash
  python main.py --config ./my_config.yaml
  ```

דוחות נשמרים ב־`./reports` (או בתיקייה שמוגדרת ב־`reporting.output_dir`) בפורמט HTML ו־JSON.

## מודל עסקי (תזכורת)

- להפעיל את הבוט רק על חברות שנתנו הרשאה מפורשת (חוזה/הסכם בדיקת אבטחה).
- דוח ללקוח: "מצאנו חולשה X / פרצה Y – מומלץ לתקן"; התשלום לפי ההסכם איתך.

## רישיון

MIT.
