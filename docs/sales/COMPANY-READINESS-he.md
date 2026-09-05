# מוכנות חברה — 100% במה שבשליטת הקוד

**עודכן:** 2026-08-18  
**אימות:** `./scripts/go_live_check.sh`

---

## ✅ הושלם (במאגר)

| תחום | מה |
|------|-----|
| **מוצר** | 573 production engines, wiring 0 gaps, UI 111/111 |
| **אבטחה** | strict billing, secrets guards, RLS, MFA, audit |
| **משפטי web** | terms/privacy **EN + HE**, DPA, subprocessors, security-policy |
| **מכירות** | ספר מוצר 681 עמודים + `viewer/index.html` |
| **MSA outline** | `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` |
| **Ops** | Incident/on-call runbook, Week-1 go-live, `go_live_check.sh` |
| **SLA** | **99.95% uptime**, SEV-1 ≤ 15 דקות, on-call 24/7 | `SLA_AND_STATUS.md` |
| **Region IL** | נתונים בישראל בלבד ללקוחות פיננסיים | `.env.example` |
| **חוזר 361** | מיפוי מלא לדרישות בנק ישראל | `docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md` |
| **SIG/CAIQ** | שאלון אבטחה כולל שאלות בנקאיות | `SIG_CAIQ_PREP_QA.md` |
| **Onboarding** | מדריך הכנסת לקוח enterprise | `docs/ENTERPRISE-ONBOARDING.md` |
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
| **Alert delivery** (PagerDuty/Slack/heartbeat) | `monitoring/secrets/README.md` — **חובה לפני go-live** |
| SOC 2 Type II audit | רק אם נדרש בחוזה (12 חודשים) |
| DPA + MSA חתומים עם בנק פועלים | עורך דין שני הצדדים |

---

## פקודות יומיות

```bash
./scripts/go_live_check.sh                    # לפני כל deploy
./scripts/go_live_check.sh --live https://...   # אחרי staging
./scripts/prepare_company_delivery.sh         # לפני demo מכירות
bash scripts/generate_audit_evidence_pack.sh  # חבילת ביקורת (JSON + PDF)
```

---

## מסלולים

| מסלול | מוכן? |
|--------|--------|
| Enterprise + self-hosted + MSA | ✅ |
| בנקים / גופים פיננסיים ישראלים (חוזר 361) | ✅ |
| MSSP pilot | ✅ |
| Cloud SaaS (Paddle) | אחרי pri_* + deploy |
| Self-serve signup | אחרי SMTP + deploy |

**קוד + תיעוד: 100%. תאגיד + production live: רשימת 🔴.**

