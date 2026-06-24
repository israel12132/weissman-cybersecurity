# 00 — ביקורת שלמות מכירה ומסירה

**מטרה:** לוודא שאין חסם מסחרי למסירה — קוד, תיעוד, משפט, תפעול וחוויית לקוח.

---

## סיכום מנהלים (יוני 2026)

| תחום | סטטוס | הערות |
|------|--------|-------|
| **חיווט מנועים** | ✅ מלא | `verify_engine_wiring.mjs` → 0 פערים; 545 מנועי production |
| **תקן UI** | ✅ מלא | `weissman-ui-audit.mjs` → 94/94 דפים |
| **UX למנועי Agent** | ✅ מלא | Empty state + gates; 45 מנועים |
| **Billing / quota** | ✅ מלא | כל נתיבי enqueue; strict ב-production |
| **Guards אבטחה** | ✅ מלא | `security_startup.rs` חוסם סודות חלשים |
| **Docker stack** | ✅ מוכן בקוד | דורש `docker compose up --build` על חומרה מתאימה |
| **דפים משפטיים** | ✅ קיימים | `deploy/public/` — terms/privacy **EN+HE**, DPA |
| **Runbooks** | ✅ קיימים | Ops: `docs/operations/` + Week-1 go-live |
| **Go-live QA** | ✅ | `./scripts/go_live_check.sh` |
| **ספר מוצר (מכירות)** | ✅ **681 עמודים** | `docs/sales/viewer/index.html` |
| **MSA template** | ✅ outline | `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` |
| **מוכנות חברה (קוד)** | ✅ 100% | `docs/sales/COMPANY-READINESS-he.md` |
| **Pricing / marketing** | ✅ | 545 engines, quotas aligned, no false SOC2 audit claim |
| **וידאו / LMS** | ⚠️ פער | אין קורס וידאו מצורף — אופציונלי |
| **קטלוג Paddle חי** | ⚠️ per-deployment | חובה להגדיר `pri_*` |
| **SMTP ל-signup** | ⚠️ אם self-serve | נדרש עם `WEISSMAN_SELF_SERVE_SIGNUP=1` |
| **LLM / vLLM** | ⚠️ מודול אופציונלי | Council, General Mission |
| **שרת OAST** | ⚠️ אופציונלי | `weissman-oast-server` נפרד |

**מסקנה:** **100% מוכן בקוד ותיעוד.** Paddle live, SMTP, deploy, ח.פ., MSA חתום — מחוץ למאגר (ראו `docs/sales/COMPANY-READINESS-he.md`).

---

## מה למסור לכל לקוח

### 1. תוכנה והתקנה
- [ ] תג Git / ארtefact (Docker או systemd)
- [ ] `PRODUCTION.env.template` מלא (סודות ב-vault)
- [ ] TLS + reverse proxy
- [ ] Postgres 16 + pgvector, Redis 7
- [ ] Migrations (`WEISSMAN_MIGRATE_URL`)

### 2. תיעוד
- [ ] `docs/manuals/README-he.md` או `README-en.md`
- [ ] `docs/sales/viewer/index.html` — ספר מוצר CEO
- [ ] `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` → עורך דין
- [ ] `SECURITY_AND_COMPLIANCE.md`, `SIG_CAIQ_PREP_QA.md`
- [ ] `SLA_AND_STATUS.md`
- [ ] `ONBOARDING_RUNBOOK.md`

### 3. משפטי ומסחרי
- [ ] MSA / SOW + **scope מורשה**
- [ ] DPA אם נדרש (`deploy/public/dpa.html`)
- [ ] Paddle או self-hosted עם חוזה
- [ ] איש קשר לת incidents

### 4. גישה
- [ ] Admin ללא סיסמה default
- [ ] MFA (ספר 07)
- [ ] טוקני Agent (אם ב-scope)
- [ ] SSO (אם נמכר)

### 5. קבלה
- [ ] ספר **18-qa-verification** חתום
- [ ] לקוח demo, סריקה, findings + PDF
- [ ] Agent online (אם רלוונטי)

---

## פערים ידועים ופתרונות

| פער | השפעה | פתרון |
|-----|--------|--------|
| `GETTING_STARTED.md` legacy | בלבול | **תוקן** — מפנה ל-manuals + `go_live_check.sh` |
| אין וידאו הדרכה | אימוץ איטי | workshop חי + חבילה זו |
| AI דורש LLM | Council/Mission idle | `WEISSMAN_LLM_BASE_URL` |
| בינארי Agent per OS | התקנה נכשלת | `scripts/package_agent_binaries.sh` |
| מכונה חלשה — אין Docker build | אין הוכחת runtime | QA על VPS staging |

---

## מה מותר / אסור לטעון במכירות

**מותר:**
- 530+ מנועים עם probes אמיתיים (ללא findings מזויפים)
- RLS multi-tenant, JWT + MFA, RBAC, audit
- Agent + 45+ משטחי detection
- SOAR, attack-path, KEV/EPSS
- Billing Paddle + מכסות
- Docker / systemd / Kubernetes

**אסור בלי הגדרה:**
- "AI red team מלא" בלי LLM
- "OOB verification" בלי OAST
- "Self-serve signup" בלי SMTP + DNS
- "SLA 99.9%" בלי חוזה + monitoring

---

## Checklist לפני דמו (30 דקות)

1. `curl -sf https://<host>/api/health`
2. Login → Command Center
3. `GET /api/engines/capabilities`
4. לקוח demo עם domain מורשה
5. סריקת מנוע אחד → job completed
6. Findings + PDF
7. Agent online (אם נמכר)

---

## ספרים קשורים

- [01-platform-overview](01-platform-overview.md)
- [18-qa-verification](18-qa-verification.md)
- [05-production-security](05-production-security.md)
- [Week-1 go-live](../../sales/WEEK-1-GOLIVE-he.md)
- [Incident/on-call](../../operations/INCIDENT-ONCALL-RUNBOOK-he.md)
