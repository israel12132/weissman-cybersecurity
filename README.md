# Security Assessment Bot

בוט להערכת אבטחה לחברות: מחובר ל־5 מקורות מודיעין (CVE, GitHub, OSV, OTX, HIBP), מזהה חולשות ופרצות רלוונטיות ללקוח לפי ה־scope שאושר, ומפיק דוחות (כולל דוח שעתי).

> **שימו לב (פערים מול מציאות / מה באמת רץ):** הריפו הזה כולל שני מסלולים:
> 1) **Weissman Platform (Rust + Frontend)** — שרת API + Worker + Command Center (מומלץ להרצה באמצעות Docker Compose).
> 2) **Python CLI Bot** (`python main.py`) — כלי קורלציה/דוחות מבוסס פידים, ללא שרת Web (קיים לצרכי כלים/אודיטים/דוחות).

## דרישות

- להרצה מלאה של הפלטפורמה: **Docker + Docker Compose**
- להרצה Native של הפלטפורמה (ללא Docker): **Rust + Cargo** + PostgreSQL (+ Redis אם צריך)
- לכלי ה־CLI בפייתון: **Python 3.10+**
- הרשאה מפורשת מלקוח לפני כל סריקה/בדיקה על הנכסים שלו

## מה המערכת יודעת לעשות

- לנהל לקוחות, scope מורשה, טווחי IP ו־tech stack.
- להריץ סריקות ו־jobs בזמן אמת, כולל מעקב סטטוס ודשבורד Jobs.
- לאסוף מודיעין מ־NVD, GitHub, OSV, OTX ו־HIBP ולהצליב אותו מול ה־scope.
- לבצע fingerprinting, fuzzing, OAST, supply-chain checks ו־dark web intel.
- להפיק דוחות PDF/CSV, findings לפי חומרה, והתראות.
- לתמוך ב־RBAC, MFA, SSO, audit logs ו־multi-tenancy.
- לעבוד עם Command Center עשיר בזמן אמת דרך WebSocket ו־live events.

## התקנה

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
# ערוך config.yaml: הוסף לקוחות, scope, ומפתחות API (אופציונלי)

# אופציונלי לכלי ה־Python: מנוע Fingerprinting (Rust) לזיהוי טכנולוגיות מכתובות ה-scope:
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

### הפעלת הפלטפורמה (Command Center + API + Worker)

```bash
# הפעלה מלאה עם Docker (מומלץ):
docker compose up --build

# או הפעלה native (ללא Docker; דורש DATABASE_URL):
./start_weissman.sh
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

### Python CLI (ללא ממשק / ללא שרת Web)

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
