# Weissman Cybersecurity — ספרי הוראות (עברית)

**גרסה:** 2026-06-20  
**קהל יעד:** מהנדסי מכירות, מפעילי SOC, מנהלי פלטפורמה, Customer Success, רכש ואבטחת מידע

תיקייה זו היא **חבילת התיעוד הרשמית למסירה** של פלטפורמת Weissman Cybersecurity. כל נושא בקובץ נפרד. השתמשו באינדקס ופתחו רק את מה שצריך.

---

## איך משתמשים בחבילה

| תפקיד | התחילו כאן | ואז |
|--------|------------|-----|
| **מכירות / Pre-Sales** | [00-sales-delivery-readiness](he/00-sales-delivery-readiness.md) | [01-platform-overview](he/01-platform-overview.md), [08-billing-multitenancy](he/08-billing-multitenancy.md) |
| **DevOps / SRE** | [02-installation-docker](he/02-installation-docker.md) | [05-production-security](he/05-production-security.md), [16-operations-monitoring](he/16-operations-monitoring.md) |
| **אנליסט SOC** | [09-client-onboarding](he/09-client-onboarding.md) | [10-scans-engines-jobs](he/10-scans-engines-jobs.md), [11-findings-reports](he/11-findings-reports.md) |
| **צוות Endpoint** | [12-endpoint-agent](he/12-endpoint-agent.md) | [10-scans-engines-jobs](he/10-scans-engines-jobs.md) |
| **ביקורת אבטחה** | [05-production-security](he/05-production-security.md) | שורש: `SECURITY_AND_COMPLIANCE.md`, `SIG_CAIQ_PREP_QA.md` |
| **QA / קבלה** | [18-qa-verification](he/18-qa-verification.md) | [17-troubleshooting](he/17-troubleshooting.md) |

---

## אינדקס ספרים (עברית)

| # | קובץ | נושא |
|---|------|------|
| 00 | [00-sales-delivery-readiness.md](he/00-sales-delivery-readiness.md) | ביקורת שלמות מכירה, פערים, רשימת מסירה ללקוח |
| 01 | [01-platform-overview.md](he/01-platform-overview.md) | שכבות המוצר, ארכיטקטורה, מנועים, זרימת נתונים |
| 02 | [02-installation-docker.md](he/02-installation-docker.md) | התקנה ב-Docker Compose (מסלול מומלץ) |
| 03 | [03-installation-vps-systemd.md](he/03-installation-vps-systemd.md) | VPS / bare-metal עם systemd |
| 04 | [04-installation-kubernetes.md](he/04-installation-kubernetes.md) | Kubernetes, Secrets, Ingress |
| 05 | [05-production-security.md](he/05-production-security.md) | הקשחה, סודות, cookies, פעולות הרסניות |
| 06 | [06-environment-configuration.md](he/06-environment-configuration.md) | `.env`, משתני סביבה עיקריים |
| 07 | [07-authentication-rbac-mfa.md](he/07-authentication-rbac-mfa.md) | התחברות, תפקידים, MFA, סessions |
| 08 | [08-billing-multitenancy.md](he/08-billing-multitenancy.md) | דיירים, Paddle, מכסות, תוכניות |
| 09 | [09-client-onboarding.md](he/09-client-onboarding.md) | Scope מורשה, ROE, סריקה ראשונה, חירום |
| 10 | [10-scans-engines-jobs.md](he/10-scans-engines-jobs.md) | מנועים, Command Center, Jobs, לוחות זמנים |
| 11 | [11-findings-reports.md](he/11-findings-reports.md) | טriage, סטטוסים, PDF/CSV |
| 12 | [12-endpoint-agent.md](he/12-endpoint-agent.md) | התקנת Agent, טוקן, detections |
| 13 | [13-integrations-cicd.md](he/13-integrations-cicd.md) | Webhooks, CI/CD, feeds, OAST |
| 14 | [14-sso-identity.md](he/14-sso-identity.md) | OIDC, SAML |
| 15 | [15-alerting-soar-ai.md](he/15-alerting-soar-ai.md) | התראות, Playbooks, Council, AI |
| 16 | [16-operations-monitoring.md](he/16-operations-monitoring.md) | Metrics, Prometheus, גיבויים |
| 17 | [17-troubleshooting.md](he/17-troubleshooting.md) | תקלות נפוצות ופתרונות |
| 18 | [18-qa-verification.md](he/18-qa-verification.md) | רשימת בדיקות לפני מסירה |

---

## מסמכים נוספים במאגר

| מסמך | מיקום |
|------|--------|
| התחלה מהירה (legacy) | `/GETTING_STARTED.md` |
| Runbook onboarding | `/ONBOARDING_RUNBOOK.md` |
| אבטחה ותאימות | `/SECURITY_AND_COMPLIANCE.md` |
| SLA | `/SLA_AND_STATUS.md` |
| ארכיטקטורה | `/docs/architecture.md` |
| תבנית Production | `/PRODUCTION.env.template` |
| משפטי (אתר) | `/deploy/public/terms.html`, `privacy.html`, `dpa.html` |
| תדריך מנהלים (עברית) | `/Weissman_Cybersecurity_מסמך_טכני_מנהלי_עברית.md` |

---

## English manuals

See [README-en.md](README-en.md) — same structure in English.
