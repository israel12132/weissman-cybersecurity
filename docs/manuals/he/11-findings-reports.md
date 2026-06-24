# 11 — Findings & Reports

## מטרה

Triage של findings, workflow סטטוסים, העשרה ב-KEV/EPSS, ייצוא PDF/CSV ללקוח, proof קריפטוגרפי במקומות רלוונטיים.

---

## דרישות מקדימות

- תפקיד analyst+ לשינוי סטטוס
- לפחות סריקה אחת שהושלמה (ספר 10)
- intel feeds (אופציוני): `WEISSMAN_INTEL_KEV_ENABLED`, `WEISSMAN_INTEL_EPSS_ENABLED`

---

## מודל נתונים

Findings ב-PostgreSQL `vulnerabilities` (RLS לפי tenant).

| שדה | תיאור |
|------|--------|
| `signature` | dedup — אותה בעיה upsert |
| `severity` | Critical / High / Medium / Low / Info |
| `engine_id` | מנוע מקור |
| `client_id` | client |
| `status` | workflow triage |
| `kev`, `epss` | העשרה |

**עקרון:** findings מ-**probes חיים** בלבד. מנועי agent — empty כנה, לא CVEs מזויפים.

---

## משטחי Command Center

| נתיב | תפקיד |
|------|--------|
| `/command-center/findings` | מרכז findings |
| פאנלים ב-hubs | לפי מנוע |
| dashboard client | scoped |
| `/command-center/reports` | דוחות |

`scripts/weissman-ui-audit.mjs` — 94/94 עמודים עם refresh, export, search.

---

## שלב אחר שלב: triage

### 1. Findings Command Center

סינון: client, severity, engine, status, תאריך. חיפוש גלובלי.

### 2. סקירה

- target ב-scope?
- true/false positive
- תג KEV (CISA)
- EPSS ל-prioritization

### 3. עדכון status

| Status | משמעות |
|--------|--------|
| `open` | חדש |
| `confirmed` | TP מאומת |
| `false_positive` | לא actionable |
| `accepted_risk` | סיכון מקובל |
| `remediated` | תוקן |
| `closed` | סופי |

analyst+ נדרש.

### 4. הערות אנליסט

תיעוד reasoning, ticket IDs, הנחיות remediation.

### 5. פעולות bulk

בחירה מרובה — status/export. סקירה לפני אישור.

---

## ייצוא דוחות

### PDF

**Reports** → Generate — סיכום מנהלים, findings לפי חומרה, scope/ROE, metadata.

### CSV

**Export CSV** — id, client, engine, severity, status, title, target, timestamps, KEV/EPSS.

ל-SIEM, ticketing, spreadsheets.

### Crypto proof

מנועים נבחרים — bundles עם hash chain לתיעוד מחלוקות.

---

## Threat intel

Workers:

- **CISA KEV** (`WEISSMAN_INTEL_KEV_ENABLED`)
- **FIRST EPSS** (`WEISSMAN_INTEL_EPSS_ENABLED`)

תגים אוטומטיים ל-CVE. air-gap — mirror מקומי.

---

## קישור להתראות

Critical findings → alert rules (ספר 15). SOAR → tickets מ-`confirmed`.

---

## אימות

```bash
curl -sf -b cookies.txt 'https://localhost/api/findings?limit=10' | jq '.findings | length'
```

- [ ] finding מסריקת בדיקה
- [ ] שינוי status נשמר
- [ ] CSV נפתח
- [ ] PDF עם footer scope
- [ ] KEV/EPSS על CVE

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| כפילויות | dedup לפי signature |
| KEV חסר | intel worker; env |
| export ריק | סינון; findings קיימים |
| PDF נכשל | logs; מקום בדיסק |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [15-alerting-soar-ai](15-alerting-soar-ai.md)
- [18-qa-verification](18-qa-verification.md)
