<div dir="rtl">

# ספר הפעלה — Weissman Command Center
### מדריך מלא למערכת: לוחות, מסלולי עבודה, ו-573 מנועי אבטחה

**גרסה:** 2026-06-20  
**קהל:** מפעיל SOC, אנליסט, מנהל MSSP, מהנדס מכירות טכני  
**היקף:** כל לוח ב-Command Center + אנציקלופדיית מנועים  
**נתיב בסיס:** `https://<your-host>/command-center/`

---

## תוכן עניינים

### חלק א׳ — יסודות
1. [איך לקרוא את הספר](#1-איך-לקרוא-את-הספר)
2. [מפת המערכת ב-30 שניות](#2-מפת-המערכת)
3. [סולם מורכבות הלוחות (קטן → גדול)](#3-סולם-מורכבות)
4. [מסלול יום-אחד (Quick Path)](#4-מסלול-יום-אחד)

### חלק ב׳ — לוחות לפי קבוצות ניווט
5. [ליבה ראשית (Primary)](#5-ליבה-ראשית)
6. [פיקוד (Command)](#6-פיקוד)
7. [מודיעין (Intelligence)](#7-מודיעין)
8. [תפעול (Operations)](#8-תפעול)
9. [מרכזי מנועים (Engine Hubs)](#9-מרכזי-מנועים)
10. [ממשל וציות (Governance)](#10-ממשל)
11. [ניהול (Administration)](#11-ניהול)
12. [לוחות נסתרים / לפי לקוח](#12-לוחות-דינמיים)

### חלק ג׳ — מנועים
13. [איך מפעילים מנוע — כללי](#13-הפעלת-מנוע)
14. [סוגי מנועים: Remote / Agent / Alias](#14-סוגי-מנועים)
15. [573 מנועים לפי קבוצה — אנציקלופedia](#15-אנציקלופedia-מנועים)

### נספחים
- [נספח א — טבלת הרשאות RBAC](#נספח-א)
- [נספח ב — מקרא סמלים](#נספח-ב)

---

## 1. איך לקרוא את הספר

כל **לוח** מתואר באותו מבנה:

| שדה | משמעות |
|-----|--------|
| **מה זה** | תפקיד הלוח במערכת |
| **מתי** | באיזה שלב engagement |
| **למה** | איזה ערך עסקי / אבטחתי |
| **מה צריך** | לקוח, scope, Agent, תפקיד, billing |
| **מסלול עבודה** | צעדים ב-UI |
| **טיפים** | מניעת טעויות |

כל **מנוע** בחלק ג׳ כולל: מזהה, MITRE, האם remote/agent, האם יעד חובה, תיאור.

> **עקרון Weissman:** אין findings מזויפים. מנוע שדורש Agent יציג empty state עד ש-Agent מחובר.

---

## 2. מפת המערכת

```
התחברות → Cockpit (/) → בחר לקוח → הפעל מנוע / סריקה
                ↓
         Jobs (מעקב) → Findings (triage) → Report (PDF/CSV)
                ↓
    מרכזי מנועים (JWT, IAC, Cloud…) או Engine Matrix (/engines)
```

**שכבות:**
- **לקוח (Client)** — scope מורשה (domains, IPs)
- **Job** — יחידת עבודה אסינכרונית
- **Finding** — תוצאת probe אמיתית
- **Engine** — מודול בדיקה (573 ברישום UI)

---

## 3. סולם מורכבות

| רמה | דוגמאות | מה עושים |
|-----|---------|----------|
| **0 — מערכת** | Login, Status | כניסה, בדיקת בריאות |
| **1 — KPI** | Rate Limits, Metrics | ניטור מגבלות / ביצועים |
| **2 — רשימות** | Clients, Jobs, Findings | CRUD + סינון |
| **3 — לוח יחיד** | JWT Lab, Email Posture | מנוע מרכזי + סריקה |
| **4 — Hub רב-מנועי** | Supply Chain, OT-ICS, Cloud | כמה מנועים + findings משולבים |
| **5 — Cockpit / CEO** | `/`, `/ceo` | תמונת מצב + שליטה אסטרטגית |

---

## 4. מסלול יום-אחד

1. **Login** → `/command-center/login`
2. **Clients** → `+ לקוח חדש` → domains מורשים
3. **Client Detail** → `Launch Scan` (או מנוע בודד)
4. **Jobs** → המתן ל-`completed`
5. **Findings** → triage לפי severity
6. **Report** → PDF ללקוח

---

## 5. ליבה ראשית

### 5.1 לקוחות — `/clients`

| | |
|--|--|
| **מה** | רשימת ארגוני לקוח ו-scope |
| **מתי** | תמיד — לפני כל סריקה |
| **למה** | Weissman לא סורק בלי scope מוגדר |
| **צריך** | תפקיד `operator+`, billing פעיל (production) |

**מסלול:** Clients → Add → שם + email + domains (שורה לשורה) → Create → Client Detail.

**טיפ:** wildcard `*.example.com` רק אם מורשה בכתב.

---

### 5.2 לקוח חדש — `/clients/new`

טופס onboarding. אחרי Create → redirect ל-Client Detail.

---

### 5.3 פרטי לקוח — `/clients/:id`

| | |
|--|--|
| **מה** | מרכז שליטה ללקוח בודד |
| **מתי** | כל engagement |
| **למה** | Launch scan, config, findings, graph |

**מסלול:**
1. ודא domains ב-scope
2. **Launch Scan** — סריקה מלאה (כל המנועים המופעלים)
3. **Configure** — enabled engines, ROE, stealth
4. **View Findings** / **Generate Report**
5. קישורים: Engagements, Evidence Vault, SaaS-IDP Discovery

**Engagements** `/clients/:id/engagements` — ניהול תקופות engagement.  
**Evidence Vault** `/clients/:id/evidence` — אחסון ראיות.  
**SaaS-IDP Discovery** `/clients/:id/discovery/saas-idp` — גילוי SaaS/IdP.

---

### 5.4 מנועים (Matrix) — `/engines`

| | |
|--|--|
| **מה** | מטריצת 573 מנועים לפי קבוצות |
| **מתי** | בחירת מנוע ספציפי, enable/disable |
| **למה** | שליטה granular על מה רץ ב-run-all |

**מסלול:** סנן קבוצה → לחץ מנוע → Engine Detail → Run Scan.

---

### 5.5 פרופיל מנוע — `/engines/:engineId`

| | |
|--|--|
| **מה** | דף מנוע בודד — היסטוריה, run, export |
| **מתי** | בדיקה ממוקדת (JWT, asm, …) |
| **צריך** | Agent אם `agent_required` (empty state אחרת) |

**מסלול:** בחר client → target → Run → עקוב ב-Jobs.

**Top-Tier** `/engines/top-tier/:id` — מנועי APT מתקדמים.  
**Business** `/engines/business/:id` — פרופיל עסקי.  
**Strategic** `/engines/strategic` — תוכנית אסטרטגית.

---

### 5.6 Billing — `/billing`

| | |
|--|--|
| **מה** | מנוי Paddle, שימוש, quota |
| **מתי** | לפני scale; כשסריקה נחסמת (402/429) |
| **צריך** | `admin` ל-checkout |

---

### 5.7 Playbooks — `/playbooks`

| | |
|--|--|
| **מה** | SOAR — when/do rules |
| **מתי** | אוטומציה על findings (Slack, webhook, status) |
| **צריך** | findings קיימים; webhook URLs |

**מסלול:** Create → תנאי (severity, KEV) → פעולות → Fire test.

---

### 5.8 Ask Weissman — `/ask`

| | |
|--|--|
| **מה** | שאילתות NL→SQL (read-only) |
| **מתי** | שאלות על נתונים ב-DB |
| **צריך** | LLM; role מתאים; audit נרשם |

---

### 5.9 Vuln Intel — `/vuln-intel`

| | |
|--|--|
| **מה** | CVE, KEV, EPSS dashboard |
| **מתי** | הקשר ל-findings |
| **למה** | prioritization מבוסס exploitability |

---

## 6. פיקוד

### 6.1 Cockpit — `/` (בדיוק)

| | |
|--|--|
| **מה** | דף הבית — KPI, telemetry SSE, סקירה |
| **מתי** | כל כניסה למערכת |
| **מסלול** | בחר client → KPIs → קפיצה ל-findings/jobs |

---

### 6.2 Findings — `/findings`

| | |
|--|--|
| **מה** | כל הממצאים cross-client |
| **מתי** | triage יומי |
| **מסלול** | סנן severity/client → פתח finding → שנה status → export CSV |

**סטטוסים:** OPEN → ACKNOWLEDGED → IN_PROGRESS → FIXED / FALSE_POSITIVE

---

### 6.3 Jobs — `/jobs`

| | |
|--|--|
| **מה** | תור async — queued/running/completed/failed |
| **מתי** | אחרי כל Run / Launch Scan |
| **מסלול** | Auto-refresh → לחץ job → status_url / findings count |

---

## 7. מודיעין

### 7.1 Threat Intel Hub — `/threat-intel`

feeds, ingest, correlation. **Run ingest** → job `threat_ingest_run` (צורך quota).

### 7.2 Threat Hunting — `/threat-hunting`

חיפוש patterns, hypotheses על findings.

### 7.3 Threat Analysis — `/threat-analysis`

ניתוח מקורות ו-correlation.

### 7.4 Dark Web — `/dark-web`

ניטור leaks (דורש feeds/API keys).

### 7.5 Intel Map — `/intel-map`

מפה גיאוגרפית/רשתית של intel.

### 7.6 Incident Response — `/incident-response`

SOC incidents, playbooks steps, timeline.

### 7.7 Zero-Day Radar — `/zero-day-radar`

component: `POST /api/threat-intel/run` — radar job.

---

## 8. תפעול

### 8.1 Threat Emulation — `/threat-emulation`

| | |
|--|--|
| **מנוע** | `threat_emulation` |
| **מתי** | סימולציית APT scenarios |
| **מסלול** | בחר client → Run → APT group findings |

### 8.2 Kill Chain — `/kill-chain`

orchestration לפי MITRE kill chain.

### 8.3 AI Analysis — `/ai-analysis`

ניתוח AI על findings (LLM).

### 8.4 Exploit Lab — `/exploit-lab`

PoE / sealed exploit workflows.

### 8.5 Council Queue — `/council-queue`

| | |
|--|--|
| **מה** | Human-in-the-loop לפני council_debate |
| **צריך** | LLM; billing; approve → job |

### 8.6 ROE Approvals — `/roe-approvals`

אישור חריגות Rules of Engagement.

### 8.7 Remediation — `/remediation`

Auto-heal proposals (destructive → header confirm).

### 8.8 Agents — `/agents`

| | |
|--|--|
| **מה** | fleet endpoint agents |
| **מתי** | לפני מנועי agent_required |
| **מסלול** | Create token → install.sh/ps1 → online_count > 0 |

### 8.9 Nexus Swarm — `/nexus-swarm`

מנוע `nexus_sovereign_swarm` — swarm orchestration.

### 8.10 Timing Profiler — `/timing-profiler`

`POST /api/timing-scan/run` — side-channel timing.

### 8.11 AI Arena — `/ai-arena`

`POST /api/ai-redteam/run` — LLM red team.

---

## 9. מרכזי מנועים

> כל Hub: **PageShell** + **ShellScanActions** (Refresh/Export) + **Run** → `POST /api/command-center/scan`

| נתיב | מנוע ראשי | מתי להשתמש |
|------|-----------|------------|
| `/attack-surface` | `asm` | mapping חיצוני ראשון |
| `/cloud` | Cloud Control Tower | AWS/Azure/GCP multi-panel |
| `/cloud-posture` | `cloud_posture` | CSPM |
| `/iac-security` | `iac_misconfig` | Terraform/K8s/Helm |
| `/graphql-security` | `graphql_attack` | API GraphQL |
| `/cicd-security` | `cicd_pipeline` | CI/CD pipelines |
| `/serverless-security` | `serverless_attack` | Lambda/Functions |
| `/dns-posture` | `bgp_dns_hijacking` | DNS/email infra |
| `/email-posture` | `email_dns_posture` | SPF/DKIM/DMARC |
| `/cache-posture` | `cache_poisoning` | Web cache |
| `/http-smuggling` | `http_smuggling` | desync |
| `/transport-security` | `mtls_grpc` | mTLS/gRPC |
| `/tls-posture` | `pki_tls` | TLS/certs |
| `/detection-surface` | `edr_evasion` | EDR surface |
| `/waf-bypass` | `waf_bypass` | WAF |
| `/websocket-security` | `websocket_attack` | WS |
| `/jwt-lab` | `jwt_attack` | JWT |
| `/file-upload-lab` | `file_upload` | uploads |
| `/identity-security` | `oauth_oidc` | OAuth/OIDC |
| `/kerberos-security` | `kerberoasting` | AD/Kerberos |
| `/smb-netbios` | `smb_netbios` | SMB |
| `/password-spray` | `password_spray` | spray (זהיר!) |
| `/saml-security` | `saml_attack` | SAML |
| `/supply-chain` | 5 מנועים | SBOM, registry, typosquat |
| `/network` | Network Intelligence | רשת |
| `/pqc-radar` | `pqc_scanner` | post-quantum |
| `/oast` | `oast_oob` | out-of-band |
| `/verification/oob` | OOB verify | אימות OAST |
| `/digital-twin` | `digital_twin` | twin sim |
| `/domain-discovery` | discovery | subdomains |
| `/mobile-security` | `mobile_attack` | mobile apps |
| `/ot-ics` | OT cards | Modbus, BACnet… |
| `/social-engineering` | `spear_phishing` | phishing sim |
| `/template-engine` | templates | nuclei-style |
| `/ast-fuzzing` | fuzz AST | |
| `/feedback-loop` | feedback fuzz | |
| `/engine-catalog` | catalog per client | |
| `/engine-reliability` | health probes | |

**מסלול Hub טיפוסי:**
1. בחר **Client** בראש הדף
2. הגדר **Target** (אם נדרש)
3. **Run Scan** / Run per card
4. **Refresh** findings
5. **Export CSV**
6. Engine Detail לעומק

---

## 10. ממשל

| נתיב | תפקיד |
|------|--------|
| `/compliance` | PCI/HIPAA/SOC mapping |
| `/sbom` | SBOM browser |
| `/risk-graph` | גраф סיכון OT/IT |
| `/baseline-drift` | UEBA drift |
| `/rate-limits` | analytics מגבלות |
| `/mobile-security` | mobile hub |
| `/ot-ics` | OT/ICS |
| `/network-protocols` | protocol lab |
| `/social-engineering` | social hub |
| `/alert-rules` | כללי התראה |
| `/containment-rules` | containment (K8s/AWS) |
| `/scan-scheduler` | cron scans (bulk billing) |

**Scan Scheduler מסלול:** Create schedule → engines + cron → Run now / wait.

---

## 11. ניהול

| נתיב | תפקיד | תפקיד RBAC |
|------|--------|------------|
| `/integrations` | webhooks, Slack | admin |
| `/identity-context` | identity metadata | operator+ |
| `/sso-config` | OIDC/SAML | admin |
| `/engine-management` | enable/disable global | admin |
| `/system-config` | system_configs keys | admin |
| `/metrics` | dashboard metrics | admin |
| `/admin` | users, tenants | admin |
| `/ceo` | God mode telemetry | ceo |
| `/ceo-vault` | secrets vault | ceo |
| `/audit-log` | audit trail | admin |
| `/system-core` | system core UI | admin |
| `/operations` | alt cockpit | operator+ |

---

## 12. לוחות דינמיים

| נתיב | תפקיד |
|------|--------|
| `/report/:clientId` | דוח PDF |
| `/attack-surface-graph/:clientId` | גраф ASM |
| `/semantic-logic/:clientId` | semantic fuzz UI |
| `/attack-chain/:clientId` | attack chain view |
| `/cicd-matrix/:clientId` | CI/CD matrix |
| `/memory-lab/:clientId` | memory forensics |
| `/timing-profiler/:clientId` | timing per client |
| `/ai-arena/:clientId` | AI red team per client |
| `/digital-twin/:clientId` | twin per client |

---

## 13. הפעלת מנוע

### שלוש דרכים

| דרך | איפה | API |
|-----|------|-----|
| **A** | Engine Detail / Hub | `POST /api/command-center/scan` |
| **B** | Client → Launch Scan | run-all engines enabled |
| **C** | Engine Matrix bulk | run-all per client |

### לפני Run

- [ ] Client עם scope
- [ ] Billing quota (production)
- [ ] Agent online (if agent_required)
- [ ] Target URL/domain תקין
- [ ] ROE mode מתאים (`safe_proofs` default)

### אחרי Run

1. Jobs → status
2. Findings → triage
3. Report → deliver

---

## 14. סוגי מנועים

| סוג | Badge | Remote? | הפעלה |
|-----|-------|---------|--------|
| `real_probe` | Live | ✓ | Run מיד |
| `agent_required` | Agent | ✗ | Agent קודם |
| `alias` | Alias | תלוי canonical | כמו canonical |
| `special` | Special | job path | async job |

API: `GET /api/engines/capabilities`

---

## 15. אנציקלופedia מנועים

> **573 מנועים** ב-16 קבוצות. לכל מנוע: מזהה, MITRE, האם remote/agent, יעד חובה, תיאור.

**Remote (✓)** = probe מהשרת ללא Agent.  
**Agent (חובה)** = Weissman Agent על host ב-scope.

---

## נספח א — RBAC

| תפקיד | Clients | Scan | Admin | CEO |
|--------|---------|------|-------|-----|
| viewer | read | ✗ | ✗ | ✗ |
| analyst | read | מוגבל | ✗ | ✗ |
| operator | CRUD | ✓ | ✗ | ✗ |
| admin | ✓ | ✓ | ✓ | ✗ |
| ceo | ✓ | ✓ | ✓ | ✓ |

Login: `POST /api/login`

---

## נספח ב — מקרא

| סמל | משמעות |
|-----|--------|
| ✓ Remote | סריקה מהענן/שרת |
| **Agent חובה** | endpoint agent |
| כן (יעד) | domain/URL required |
| ROE | Rules of Engagement |

---

*המשך: אנציקלופדיית המנועים החיה ב-[`_engines-appendix-generated.md`](./_engines-appendix-generated.md) — מחולל `node scripts/generate_system_book_engines.mjs`.*

</div>
