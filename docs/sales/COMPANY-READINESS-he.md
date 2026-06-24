# מוכנות חברה — 100% במה שבשליטת הקוד

**עודכן:** אוטומטי עם כל `scripts/prepare_company_delivery.sh`  
**גבול:** פריטים שדורשים עורך דין / רו"ח / תשתית production — מסומנים 🔴

---

## ✅ הושלם (במאגר)

| תחום | מה |
|------|-----|
| **מוצר** | 545 production engines, wiring 0 gaps, UI 94/94 |
| **אבטחה** | strict billing, secrets guards, RLS, MFA, audit |
| **משפטי web** | terms, privacy, DPA, subprocessors, security-policy, security.txt |
| **מכירות** | ספר מוצר 681 עמודים + `viewer/index.html` |
| **MSA outline** | `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` |
| **Pricing** | 545 engines, quotas aligned with DB, no false SOC2 Type II claim |
| **Staging package** | `docker-compose.staging.yml`, env example, QA script |
| **Manuals** | 19 ספרים HE+EN + Command Center book |

---

## 🔴 מחוץ לקוד — אתה / עו"ד / רו"ח

| פריט | פעולה |
|------|--------|
| רישום בע"מ + **ח.פ.** | רשם החברות → עדכן `deploy/company.details.example.json` |
| MSA חתום | מתווה ב-`docs/legal/` → עורך דין |
| חשבון בנק + חשבוניות מע"מ | רו"ח |
| מיילים `@weissman.io` | DNS + Google Workspace / similar |
| ביטוח סייבר | סוכן |
| Paddle **live** `pri_*` | Dashboard + `.env` |
| Production deploy + TLS | VPS / cloud |
| SOC 2 Type II audit | אם נדרש בחוזה — תהליך חיצוני |

---

## הרצה — אימות לפני מכירה

```bash
./scripts/prepare_company_delivery.sh
```

Pass = QA + encyclopedia + wiring.

---

## הצגה ל-CEO / Enterprise

1. `docs/sales/viewer/index.html`
2. `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` (לעו"ד)
3. `deploy/public/terms.html` + DPA
4. Demo: Clients → Scan → Findings → PDF

---

## סטטוס מסחרי

| מסלול | מוכן? |
|--------|--------|
| Enterprise + MSA + self-hosted | ✅ מוצר + תיעוד |
| MSSP pilot | ✅ |
| Cloud SaaS (Paddle) | ⚠️ אחרי `pri_*` + deploy |
| Self-serve signup | ⚠️ אחרי SMTP + deploy |

**בשליטת הקוד: 100%. בשליטת התאגיד: רשימת 🔴 למעלה.**
