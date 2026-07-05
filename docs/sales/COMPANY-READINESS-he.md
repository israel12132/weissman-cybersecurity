# מוכנות חברה — 100% במה שבשליטת הקוד

**עודכן:** 2026-06-24  
**אימות:** `./scripts/go_live_check.sh`

---

## ✅ הושלם (במאגר)

| תחום | מה |
|------|-----|
| **מוצר** | 559 production engines, wiring 0 gaps, UI 95/95 |
| **אבטחה** | strict billing, secrets guards, RLS, MFA, audit |
| **משפטי web** | terms/privacy **EN + HE**, DPA, subprocessors, security-policy |
| **מכירות** | ספר מוצר 681 עמודים + `viewer/index.html` |
| **MSA outline** | `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` |
| **Ops** | Incident/on-call runbook, Week-1 go-live, `go_live_check.sh` |
| **GETTING_STARTED** | מפנה ל-manuals (לא changeme legacy) |
| **Git security doc** | `docs/operations/GIT-CREDENTIALS-SECURITY.md` |
| **Staging** | compose overlay, Mailpit, OAST, QA scripts |

---

## 🔴 מחוץ לקוד — אתה / עו"ד / רו"ח / VPS

| פריט | פעולה |
|------|--------|
| רישום בע"מ + **ח.פ.** | → `deploy/company.details.json` (לא ב-git) |
| MSA חתום | עורך דין |
| Paddle **live** `pri_*` | Dashboard |
| Production VPS + TLS | `./scripts/go_live_check.sh --live URL` |
| `@weissman.io` mailboxes | DNS |
| ביטוח סייבר | סוכן |
| SOC 2 Type II audit | רק אם נדרש בחוזה |

---

## פקודות יומיות

```bash
./scripts/go_live_check.sh                    # לפני כל deploy
./scripts/go_live_check.sh --live https://...   # אחרי staging
./scripts/prepare_company_delivery.sh         # לפני demo מכירות
```

---

## מסלולים

| מסלול | מוכן? |
|--------|--------|
| Enterprise + self-hosted + MSA | ✅ |
| MSSP pilot | ✅ |
| Cloud SaaS (Paddle) | אחרי pri_* + deploy |
| Self-serve signup | אחרי SMTP + deploy |

**קוד + תיעוד: 100%. תאגיד + production live: רשימת 🔴.**
