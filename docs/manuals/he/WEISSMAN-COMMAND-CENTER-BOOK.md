<div dir="rtl">

# ספר הפעלה — Weissman Command Center
### מדריך מלא למערכת: לוחות, מסלולי עבודה, ו-533 מנועי אבטחה

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
15. [533 מנועים לפי קבוצה — אנציקלופedia](#15-אנציקלופedia-מנועים)

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
- **Engine** — מודול בדיקה (533 ברישום UI)

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
| **מה** | מטריצת 533 מנועים לפי קבוצות |
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

> **533 מנועים** ב-14 קבוצות. לכל מנוע: מזהה, MITRE, האם remote/agent, יעד חובה, תיאור.

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

*המשך: אנציקלופediית מנועים מלאה ↓*

</div>

<div dir="rtl">

<!-- AUTO-GENERATED by scripts/generate_system_book_engines.mjs — 533 engines -->

### AI / LLM (`ai`) — 45 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `adversarial_examples` | Adversarial Example Generator | T1588 | ✓ | — | כן | Adversarial ML examples: FGSM/PGD/CW attacks on vision models, text adversarial examples (TextFool,  |
| 2 | `adversarial_image` | Adversarial Image Attack | T1036 | ✓ | — | לא | Computer vision adversarial attacks: FGSM/PGD perturbation for classifier evasion, patch-based physi |
| 3 | `adversarial_ml` | Adversarial ML | T1562 | ✓ | — | כן | Evasion attacks against ML-based WAF, IDS, and anomaly detection models |
| 4 | `agentic_ai_escape` | Agentic AI Sandbox Escape | T1611 | ✓ | — | כן | AI agent tool abuse: code interpreter sandbox escape via subprocess, file system exfiltration throug |
| 5 | `agentic_framework_attack` | AI Agentic Framework Exploitation | T1059.008 | ✓ | — | כן | LangChain/LlamaIndex/CrewAI/AutoGPT/Semantic Kernel exploitation: chain injection for tool abuse, me |
| 6 | `ai_adversarial_redteam` | AI Adversarial Red Team | T1059 | ✓ | — | כן | Adversarial prompt injection, jailbreak, and model output manipulation |
| 7 | `ai_bias_exploit` | AI Bias / Fairness Exploitation | T1565 | ✓ | — | כן | Exploiting ML model bias: demographic parity bypass for access control evasion, adversarial query cr |
| 8 | `ai_model_backdoor` | AI Model Backdoor / Trojan | T1195.001 | ✓ | — | לא | Neural network trojan insertion: BadNets trigger implantation, latent-space backdoor via fine-tuning |
| 9 | `ai_poisoning` | AI Training Data Poisoning | T1565 | ✓ | — | לא | ML model supply chain attack: training data manipulation, backdoor injection via poisoned datasets,  |
| 10 | `ai_supply_chain` | AI/ML Supply Chain Attack | T1195 | ✓ | — | לא | ML supply chain exploitation: malicious HuggingFace model injection, PyPI/conda ML package typosquat |
| 11 | `ai_supply_chain_attack` | AI Model Supply Chain Attack | T1195.001 | ✓ | — | לא | AI model supply chain compromise: Hugging Face malicious model detection, pickle deserialization in  |
| 12 | `ai_watermark_bypass` | AI Watermark / Fingerprint Removal | T1036 | ✓ | — | לא | AI output watermark defeat: paraphrase-based watermark removal, statistical watermark detection and  |
| 13 | `autonomous_ai_escape` | Autonomous AI Agent Sandbox Escape | T1059.008 | ✓ | — | כן | AI agent sandbox escape: filesystem traversal via agent tool calls, shell command injection through  |
| 14 | `autonomous_pentest` | Autonomous Pentest | T1595 | ✓ | — | כן | Fully autonomous multi-step penetration test orchestrated by AI planner |
| 15 | `data_poisoning_engine` | Training Data Poisoning Engine | T1565.001 | ✓ | — | לא | Training data poisoning attacks: backdoor trigger insertion, federated learning gradient poisoning,  |
| 16 | `deepfake_genai` | Deepfake / GenAI Attack | T1566 | ✓ | — | לא | AI-generated deepfake voice/video phishing, synthetic identity creation, vishing simulation |
| 17 | `deepfake_synthesis` | Deepfake Synthesis Engine | T1660 | ✓ | — | לא | AI-generated synthetic media for social engineering: real-time voice cloning detection, video deepfa |
| 18 | `exfil_ai_inference` | Model Inversion / Exfiltration | T1048 | ✓ | — | כן | AI model exfiltration: membership inference attacks, model stealing via repeated queries, gradient-b |
| 19 | `federated_learning_attack` | Federated Learning Poisoning | T1565.001 | ✓ | — | לא | Federated learning attack framework: gradient inversion for training data reconstruction, Byzantine  |
| 20 | `gpt_plugin_attack` | GPT Plugin / Action Exploiter | T1059.008 | ✓ | — | כן | ChatGPT plugin and GPT Action exploitation: OAuth flow hijacking in plugin authentication, plugin ma |
| 21 | `llm_agent_hijack` | LLM Agent Hijacking | T1059 | ✓ | — | כן | Autonomous AI agent exploitation: indirect prompt injection via tool outputs, memory poisoning, goal |
| 22 | `llm_context_overflow` | LLM Context Window Overflow | T1499 | ✓ | — | כן | Context window manipulation: token flooding to displace system prompt, attention dilution attack, lo |
| 23 | `llm_dos` | LLM Resource Exhaustion | T1499.004 | ✓ | — | כן | LLM denial-of-service: sponge example token amplification, repetition loop injection, recursive self |
| 24 | `llm_dos_attack` | LLM Denial of Service | T1499 | ✓ | — | כן | LLM-specific denial of service: prompt bombing (token exhaustion), repetitive infinite loop prompts, |
| 25 | `llm_function_call_hijack` | LLM Function Calling Hijack Engine | T1059.008 | ✓ | — | כן | LLM function calling and tool-use exploitation: function schema injection to forge tool calls, param |
| 26 | `llm_guardrail_bypass` | LLM Safety Guardrail Bypass Engine | T1059.008 | ✓ | — | כן | AI safety classifier and content filter bypass: adversarial suffix generation (GCG/AutoDAN) for poli |
| 27 | `llm_jailbreak` | LLM Jailbreak / Prompt Extraction | T1059 | ✓ | — | כן | LLM jailbreak techniques: system-prompt extraction, role-play injection, indirect prompt injection v |
| 28 | `llm_memory_extraction` | LLM Memory Extraction | T1552 | ✓ | — | כן | LLM conversation memory attacks: system prompt extraction via indirect questioning, few-shot example |
| 29 | `llm_path_fuzz` | LLM Path Fuzz | T1190 | ✓ | — | כן | LLM-generated endpoint path fuzzing tailored to detected tech stack |
| 30 | `llm_privacy_leak` | LLM Training Data Extraction | T1530 | ✓ | — | כן | Membership inference and data extraction: verbatim training data recall prompts, differential privac |
| 31 | `llm_red_team_advanced` | Advanced LLM Red Teaming | T1059.008 | ✓ | — | כן | Systematic LLM red teaming: automated jailbreak generation via tree-of-thought, GCG/AutoDAN adversar |
| 32 | `llm_redteam` | LLM Red Team | T1059 | ✓ | — | כן | Structured LLM red-teaming: role confusion, data leakage, context overflow |
| 33 | `llm_system_prompt_leak` | System Prompt Extraction | T1530 | ✓ | — | כן | System prompt leakage: direct prompt disclosure via roleplay, token-by-token probability extraction, |
| 34 | `mcp_server_exploit` | Model Context Protocol (MCP) Exploit | T1059.008 | ✓ | — | כן | Model Context Protocol exploitation: malicious MCP server impersonation for tool poisoning, resource |
| 35 | `model_inversion_attack` | ML Model Inversion Attack | T1588.005 | ✓ | — | כן | Machine learning model inversion: membership inference attacks, model extraction/stealing via query  |
| 36 | `model_stealing_engine` | ML Model Stealing Engine | T1588.005 | ✓ | — | כן | Machine learning model extraction: black-box model stealing via query budget optimization, functiona |
| 37 | `multi_agent_subversion` | Multi-Agent AI Subversion Engine | T1059.008 | ✓ | — | כן | Multi-agent AI system attacks: trust exploitation between AI agents in a pipeline, Byzantine agent i |
| 38 | `multimodal_ai_attack` | Multimodal AI Attack | T1059 | ✓ | — | כן | Vision-language model attacks: adversarial patch injection into images, audio transcription jailbrea |
| 39 | `neural_backdoor_detect` | Neural Network Backdoor Detector | T1588.005 | ✓ | — | לא | Neural network backdoor detection and exploitation: trigger pattern identification via Neural Cleans |
| 40 | `nexus_sovereign_swarm` | Nexus Sovereign Swarm Intelligence | T1595 | ✓ | — | כן | Hyper-scale hive-mind deployment of thousands of AI micro-agents with emergent consensus intelligenc |
| 41 | `prompt_injection_chain` | Prompt Injection Chain Attack | T1059.008 | ✓ | — | כן | Chained prompt injection attacks: indirect PI via document/email/web content, tool call hijacking in |
| 42 | `rag_poisoning` | RAG / Vector DB Poisoning | T1565 | ✓ | — | כן | Retrieval-Augmented Generation attack: adversarial document injection, embedding space poisoning, co |
| 43 | `rag_poisoning_engine` | RAG System Poisoning | T1565 | ✓ | — | כן | Retrieval-Augmented Generation poisoning: vector database injection via adversarial documents, embed |
| 44 | `semantic_ai_fuzz` | Semantic AI Fuzz | T1059 | ✓ | — | כן | Semantically-aware fuzzing using language models to infer application logic |
| 45 | `synthetic_identity_fraud` | AI Synthetic Identity Fraud Engine | T1534 | ✓ | — | לא | AI-generated synthetic identity for fraud and social engineering: GAN-generated photo-realistic iden |

### APT / Top-Tier (`apt`) — 60 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `active_directory` | Active Directory Attack | T1558 | ✓ | — | כן | DCSync, Pass-the-Hash, Golden/Silver Ticket, NTLM relay, AS-REP Roasting, BloodHound path abuse |
| 2 | `advanced_persistence` | Advanced Persistence (UEFI / Bootkit) | T1542 | ✓ | — | לא | Nation-state grade persistence: UEFI SPI firmware implant (MosaicRegressor-style), Secure Boot bypas |
| 3 | `ai_cloud_escalation_chain` | AI Vulnerability → Cloud Escalation Chain | T1210 | ✓ | — | כן | Novel cross-domain attack chain: AI/LLM system compromise → cloud credential extraction → IAM privil |
| 4 | `apt_c2_infra` | APT-Grade C2 Infrastructure | T1583 | ✓ | — | לא | APT C2 infrastructure emulation: Cobalt Strike malleable profile detection, Brute Ratel/Sliver evasi |
| 5 | `apt_lateral_movement` | APT Lateral Movement Playbook | T1021 | ✓ | — | כן | Advanced lateral movement TTPs: DCOM lateral movement, WMI remote execution, PSExec-less service cre |
| 6 | `apt28_techniques` | APT28 (Fancy Bear) TTPs | T1566.001 | ✓ | — | כן | APT28/Fancy Bear technique simulation: X-Agent malware indicators, spear phishing with geopolitical  |
| 7 | `apt29_techniques` | APT29 (Cozy Bear) TTPs | T1566.002 | ✓ | — | כן | APT29/Cozy Bear technique simulation: WellMess/WellMail malware patterns, Sunburst/SolarWinds-style  |
| 8 | `apt41_techniques` | APT41 (Winnti/Double Dragon) TTPs | T1195 | ✓ | — | כן | APT41 dual-purpose cyber espionage/crime TTPs: ShadowPad backdoor indicators, supply chain compromis |
| 9 | `blackcat_alphv_ttps` | BlackCat/ALPHV Ransomware TTPs | T1486 | ✓ | — | לא | BlackCat/ALPHV ransomware TTPs: Rust-based ransomware analysis (mirroring real BlackCat), BYOVD via  |
| 10 | `browser_exploitation` | Browser Exploitation | T1189 | ✓ | — | כן | JS engine RCE chains, sandbox escape, drive-by download emulation, renderer exploit surface |
| 11 | `c2_emulation` | C2 Framework Emulation | T1071.001 | ✓ | — | לא | Cobalt Strike Beacon, Sliver, Mythic, Havoc C2 simulation — beacon detection and listener fingerprin |
| 12 | `c2_rotation_engine` | Automated C2 Infrastructure Rotation Engine | T1583.001 | ✓ | — | לא | Dynamic C2 infrastructure management: automated domain generation and registration, cloud-provider r |
| 13 | `carbon_spider_ttps` | Carbon Spider (Evil Corp) TTPs | T1566.001 | ✓ | — | כן | Evil Corp/Carbon Spider criminal TTPs: WastedLocker ransomware patterns, SocGholish fake update init |
| 14 | `cl0p_techniques` | Cl0p Ransomware TTPs | T1486 | ✓ | — | כן | Cl0p ransomware group TTPs: MOVEit Transfer exploitation pattern (CVE-2023-34362), GoAnywhere MFT ex |
| 15 | `conti_ransomware_ttps` | Conti Ransomware Group TTPs | T1486 | ✓ | — | לא | Conti ransomware group technique simulation (from leaked playbook): BazarLoader initial access, Coba |
| 16 | `deception_honeypot` | Deception Honeypot | T1219 | ✓ | — | כן | Honeypot detection heuristics, canary token exposure, fake asset fingerprint |
| 17 | `destructive_wiper` | Destructive Wiper Emulation | T1485 | ✓ | — | לא | Disk-wiping destructive payload emulation: MBR overwrite, partition table destruction, recursive fil |
| 18 | `digital_twin` | Digital Twin | T1588 | ✓ | — | כן | Environment simulation with XSS, SQLi, MITM, CORS attack path modeling |
| 19 | `earth_longzhi_ttps` | Earth Longzhi APT TTPs | T1195 | ✓ | — | כן | Earth Longzhi (Trend Micro tracked) APT technique simulation: ESET-targeting BYOVD, SPHijacker stack |
| 20 | `equation_group_ttps` | Equation Group (NSA-linked) TTPs | T1542 | ✓ | — | לא | Equation Group technique simulation: DOUBLEPULSAR kernel implant detection, ETERNALBLUE SMB exploit  |
| 21 | `fin7_techniques` | FIN7 Financial Crime TTPs | T1566.001 | ✓ | — | כן | FIN7/Carbanak financial crime TTPs: Carbanak banking backdoor patterns, GRIFFON JS backdoor, fake AV |
| 22 | `full_breach_sim` | Full End-to-End Breach Simulation | T1650 | ✓ | — | כן | Complete kill chain emulation: recon → initial access → execution → persistence → privilege escalati |
| 23 | `heap_exploitation` | Heap Exploitation | T1203 | ✓ | — | לא | Heap memory exploitation: use-after-free, tcache poisoning, double-free, heap grooming, ASLR/PIE byp |
| 24 | `kernel_exploit` | Kernel Exploit | T1068 | ✓ | — | לא | Kernel privilege escalation: Dirty Pipe, eBPF program abuse, io_uring UAF, SELinux/AppArmor bypass,  |
| 25 | `kill_chain` | Kill Chain | T1210 | ✓ | — | כן | Full Cyber Kill Chain execution across Recon → Exfiltration phases |
| 26 | `lazarus_group_ttps` | Lazarus Group (DPRK) TTPs | T1566.001 | ✓ | — | לא | Lazarus Group/Hidden Cobra technique simulation: AppleJeus cryptocurrency theft patterns, BLINDINGCA |
| 27 | `lockbit_techniques` | LockBit Ransomware TTPs | T1486 | ✓ | — | לא | LockBit 2.0/3.0/Black ransomware TTPs: bug bounty program exploitation, affiliate recruitment detect |
| 28 | `log4shell_scan` | Log4Shell / Log4J | T1190 | ✓ | — | כן | CVE-2021-44228 JNDI injection scan across HTTP headers, user-agents, JSON fields, XML payloads |
| 29 | `long_haul_exfil` | Long-Haul Slow Exfiltration | T1030 | ✓ | — | כן | APT dwell-time data exfiltration simulation: 200-byte/hour slow-leak over DNS, HTTPS traffic blendin |
| 30 | `memory_corruption` | Memory Corruption | T1203 | ✓ | — | כן | Heap spray, use-after-free, ROP-chain detection, format-string, and integer overflow surface mapping |
| 31 | `midnight_blizzard_ttps` | Midnight Blizzard (APT29 Advanced) TTPs | T1566.002 | ✓ | — | כן | Midnight Blizzard (SolarWinds/Microsoft/HPE attacks): OAuth application abuse for persistent access, |
| 32 | `mobile_backend_chain` | Mobile App → Cloud Backend Escalation Chain | T1190 | ✓ | — | כן | Mobile-to-cloud attack chain: mobile app binary analysis for hardcoded credentials → API key extract |
| 33 | `nation_state_ttps` | Nation-State TTP Emulation | T1588 | ✓ | — | לא | Emulation of top APT playbooks: NOBELIUM (SolarWinds-style SWC), APT41 supply chain + espionage dual |
| 34 | `oast_oob` | OAST / OOB | T1071 | ✓ | — | כן | Out-of-band callbacks via Log4Shell JNDI, blind XSS, XXE, SSRF canaries |
| 35 | `obfuscated_c2` | Obfuscated / Domain-Fronted C2 | T1090.004 | ✓ | — | לא | Domain-fronted C2 detection: CDN SNI mismatch, encrypted DNS beacon, Tor/I2P hidden service C2, JA3/ |
| 36 | `ot_it_lateral_chain` | OT Network → IT Network Lateral Pivot Chain | T1021 | ✓ | — | כן | OT-to-IT network bridging attack chain: ICS network initial access via industrial protocol exploitat |
| 37 | `poe_synthesis` | PoE Synthesis | T1588 | ✓ | — | כן | Proof-of-Exploitation synthesis — AI-generated PoC from raw findings |
| 38 | `post_exploitation` | Post-Exploitation | T1003 | ✓ | — | כן | Automated post-exploitation: LSASS dump, SAM/NTDS.dit extraction, credential cache scraping, privile |
| 39 | `prometheus_hyperion_nexus` | PROMETHEUS HYPERION NEXUS™ — Cross-Domain AI Adversarial Swarm | T1650 | ✓ | — | לא | Cross-domain AI adversarial swarm: 14 specialized attack agents run simultaneously across every doma |
| 40 | `quantum_sovereign_nexus` | QUANTUM SOVEREIGN NEXUS - World\ | T1591 | ✓ | — | לא | The world\ |
| 41 | `ransomware_emulation` | Ransomware Emulation | T1486 | — | **חובה** | לא | Ransomware TTP emulation: staged encryption, shadow-copy wipe, ransom note delivery, backup deletion |
| 42 | `ransomware_sim` | Ransomware Simulation | T1486 | ✓ | — | לא | Ransomware TTP emulation: file enumeration, shadow-copy deletion, encryption key management audit, n |
| 43 | `rce_chain` | RCE Chain | T1203 | ✓ | — | כן | Multi-vector Remote Code Execution via deserialization, EL injection, shell metacharacter chains |
| 44 | `salt_typhoon_ttps` | Salt Typhoon Telecom TTPs | T1557 | ✓ | — | לא | Salt Typhoon APT (AT&T/Verizon breach) telecom attack simulation: lawful intercept system compromise |
| 45 | `sandworm_techniques` | Sandworm (Voodoo Bear) TTPs | T1485 | ✓ | — | לא | Sandworm/Voodoo Bear destructive TTPs: NotPetya wiper simulation, Industroyer/Crashoverride ICS atta |
| 46 | `scattered_spider_ttps` | Scattered Spider Social TTPs | T1621 | ✓ | — | כן | Scattered Spider (0ktapus) technique simulation: SMS phishing for MFA bypass, Okta admin console tak |
| 47 | `social_supply_chain_attack` | Social Engineering → Supply Chain Compromise Chain | T1195 | ✓ | — | כן | Social engineering to supply chain kill chain: LinkedIn recruiter persona → developer trust → malici |
| 48 | `supply_chain_apt` | Supply Chain APT Implant | T1195 | ✓ | — | לא | SolarWinds/3CX-style supply chain implant: build server compromise, DLL sideload via signed installe |
| 49 | `tactic_chain_synthesizer` | Novel TTP Attack Chain Synthesizer | T1650 | ✓ | — | כן | AI-powered novel attack chain synthesis: graph neural network-based TTP combination discovery, rare  |
| 50 | `threat_emulation` | APT Threat Emulation | T1583 | ✓ | — | כן | Nation-state TTP emulation: Lazarus, APT28/29/41, Sandworm, Kimsuky, Equation |
| 51 | `threat_hunting_apt` | Threat Hunting Automation | T1078 | ✓ | — | לא | Automated threat hunting: IOC correlation, YARA-rule-based artifact detection, MITRE ATT&CK heat-map |
| 52 | `unc2452_ttps` | UNC2452 (SolarWinds) TTPs | T1195.002 | ✓ | — | כן | UNC2452/Dark Halo supply chain technique simulation: DGA-based Sunburst C2, Teardrop memory-only dro |
| 53 | `unc3944_ttps` | UNC3944/Octo Tempest TTPs | T1621 | ✓ | — | כן | UNC3944 (Scattered Spider/Octo Tempest) advanced TTPs: SIM swapping for account takeover, IT helpdes |
| 54 | `volt_typhoon_ttps` | Volt Typhoon (VANGUARD PANDA) TTPs | T1078 | ✓ | — | כן | Volt Typhoon Chinese APT living-off-land techniques: SOHO router/VPN pivot infrastructure, PowerShel |
| 55 | `vuln_chaining` | Vuln Chain Synthesis | T1210 | ✓ | — | כן | Multi-CVE exploit chain synthesis: N-day stacking, CVSS-weighted kill-path scoring, auto-PoC linking |
| 56 | `watering_hole` | Watering Hole Attack | T1189 | ✓ | — | כן | Strategic web compromise: target-profile-based website compromise, browser exploit delivery via mali |
| 57 | `wizard_spider_ttps` | Wizard Spider (TrickBot/Conti) TTPs | T1566.001 | ✓ | — | לא | Wizard Spider/TrickBot group TTPs: TrickBot module analysis (networkDll, pwgrab), BazarLoader delive |
| 58 | `zero_click_exploit` | Zero-Click Exploit Emulation | T1203 | ✓ | — | כן | Zero-interaction exploitation: iMessage/NSO Pegasus-style vector analysis, FORCEDENTRY-pattern Image |
| 59 | `zero_day_chain` | Zero-Day Exploit Chain | T1203 | ✓ | — | כן | Multi-vulnerability zero-day chain simulation: browser renderer RCE → sandbox escape → kernel privil |
| 60 | `zero_day_prediction` | Zero-Day Prediction | T1212 | ✓ | — | לא | Component fingerprint + historical CVE frequency + live NVD feed analysis |

### ענן ותשתית (`cloud`) — 48 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `aws_attack` | AWS Attack | T1580 | ✓ | — | לא | IAM privilege escalation, S3 bucket exposure, Lambda event injection |
| 2 | `azure_ad_attack` | Azure AD / Entra ID Attack | T1078.004 | ✓ | — | כן | Entra ID exploitation: Primary Refresh Token (PRT) theft, device code phishing flow, Conditional Acc |
| 3 | `azure_attack` | Azure Attack | T1580 | ✓ | — | לא | Azure AD token abuse, Blob SAS exposure, Function App command injection |
| 4 | `azure_devops_attack` | Azure DevOps Pipeline Attack | T1195.002 | ✓ | — | כן | Azure DevOps exploitation: pipeline YAML injection, service connection credential theft, artifact fe |
| 5 | `cloud_audit_evasion` | Cloud Audit Log Evasion | T1562.008 | ✓ | — | לא | Cloud audit log evasion techniques: CloudTrail logging gaps exploitation, GCP audit log blind spots, |
| 6 | `cloud_cost_dos` | Cloud Cost Amplification DoS | T1499 | ✓ | — | כן | Economic denial-of-sustainability (EDoS): Lambda invocation flooding, DynamoDB scan amplification, C |
| 7 | `cloud_data_exfil` | Cloud Storage Exfiltration | T1567.002 | ✓ | — | לא | Cloud storage exfiltration channels: S3/GCS/Azure Blob covert exfiltration, presigned URL exfil, clo |
| 8 | `cloud_function_escape` | Cloud Function Runtime Escape | T1611 | ✓ | — | כן | Container/VM escape from cloud function runtime: cgroup namespace breakout, kernel exploit via share |
| 9 | `cloud_iam_escalation` | Cloud IAM Privilege Escalation | T1078.004 | ✓ | — | לא | Cloud IAM privilege escalation paths: AWS IAM policy misconfiguration enumeration (Pacu techniques), |
| 10 | `cloud_identity_attack` | Cloud Identity & IAM Attack | T1078.004 | ✓ | — | לא | Cloud IAM privilege escalation: assume-role abuse, cross-service confused deputy, service-linked rol |
| 11 | `cloud_lateral` | Cloud Lateral Movement | T1552.005 | ✓ | — | לא | Cloud-to-cloud lateral movement: IMDSv1 SSRF, IAM role chaining, cross-account pivot, EC2/GCE instan |
| 12 | `cloud_logging_blind` | Cloud Logging Blind Spot Exploit | T1562 | ✓ | — | לא | Exploiting cloud logging gaps: data plane events not logged by default, Athena query exfiltration wi |
| 13 | `cloud_metadata_ssrf` | Cloud Metadata SSRF Attack | T1552.005 | ✓ | — | כן | Cloud metadata API exploitation via SSRF: AWS IMDSv1 credential theft via SSRF chain, GCP metadata s |
| 14 | `cloud_network_attack` | Cloud Network Attack Engine | T1557 | ✓ | — | לא | Cloud network exploitation: VPC flow log evasion, security group misconfiguration detection, transit |
| 15 | `cloud_posture` | Cloud Posture Management (CSPM) | T1580 | ✓ | — | לא | Agentless AWS CNAPP — 37 live API planes (Neptune, MemoryDB, Backup, Organizations, Step Functions,  |
| 16 | `cloud_privilege_persistence` | Cloud Persistence Engine | T1098 | ✓ | — | לא | Cloud environment persistence: IAM backdoor user/role creation, Lambda function persistence, schedul |
| 17 | `cloud_ransomware` | Cloud Ransomware | T1486 | ✓ | — | לא | S3 object encryption via SSE-C key rotation, RDS snapshot hijacking, Glacier vault lock abuse |
| 18 | `cloud_storage_audit` | Cloud Storage Audit | T1530 | ✓ | — | לא | S3/GCS/Azure Blob misconfiguration: unauthenticated bucket listing, ACL bypass, presigned URL abuse, |
| 19 | `cloud_trail_disable` | Cloud Audit Log Tampering | T1562.008 | ✓ | — | לא | Cloud logging evasion: CloudTrail event deletion, GuardDuty suppressor rule injection, Azure Monitor |
| 20 | `cloud_waf_bypass` | Cloud WAF / Shield Bypass | T1562 | ✓ | — | כן | AWS Shield/WAF, Azure Front Door, Cloudflare bypass: IP rotation, TLS fingerprint cycling, ALB direc |
| 21 | `cloud_worm_propagation` | Cloud Worm Propagation Engine | T1080 | ✓ | — | לא | Cloud environment worm propagation: cross-account credential reuse, VPC peering lateral movement, sh |
| 22 | `cloudformation_injection` | CloudFormation / ARM Template Injection | T1195 | ✓ | — | כן | Infrastructure-as-Code template injection: CloudFormation parameter injection, ARM template expressi |
| 23 | `container_escape` | Container Escape | T1611 | ✓ | — | לא | Docker socket abuse, privileged container breakout, cgroups v1/v2 escape, host PID namespace takeove |
| 24 | `container_k8s_escape` | Container / K8s Escape | T1611 | ✓ | — | לא | Container breakout via privileged mode, runc CVEs, cgroup namespace escape, K8s API server abuse, ku |
| 25 | `cross_account_pivot` | Cross-Account Role Pivot | T1199 | ✓ | — | לא | AWS cross-account attacks: overly permissive trust policy exploitation, confused deputy via resource |
| 26 | `ecr_image_poison` | Container Image Poisoning | T1525 | ✓ | — | כן | Registry-level supply chain attack: ECR/GCR/GHCR malicious layer injection, image tag mutable redire |
| 27 | `ecr_registry_attack` | Container Registry Attack | T1195.001 | ✓ | — | כן | Container registry exploitation: ECR/GCR/ACR image pull secret theft, vulnerable base image detectio |
| 28 | `edge_computing_exploit` | Edge Computing Node Exploitation | T1610 | ✓ | — | כן | Edge computing security exploitation: AWS Greengrass/Azure IoT Edge/GCP Anthos bare-metal exploitati |
| 29 | `eks_attack` | EKS/AKS/GKE Managed K8s Attack | T1610 | ✓ | — | כן | Managed Kubernetes service exploitation: EKS IAM authenticator abuse, AKS managed identity container |
| 30 | `gcp_attack` | GCP Attack | T1580 | ✓ | — | לא | GCP service account key exposure, Cloud Run abuse, IAM over-permission scan |
| 31 | `gcp_privilege_attack` | GCP Privilege Escalation Engine | T1078.004 | ✓ | — | לא | Google Cloud Platform privilege escalation: service account key enumeration, impersonation chain exp |
| 32 | `gke_rbac_exploit` | Kubernetes RBAC Exploit | T1613 | ✓ | — | כן | Kubernetes RBAC privilege escalation: ClusterRole wildcard abuse, create-pod-to-root, impersonation  |
| 33 | `iac_misconfig` | IaC Security | T1059 | ✓ | — | לא | World-class Infrastructure-as-Code analysis: Terraform/Kubernetes/CloudFormation/Dockerfile/Compose/ |
| 34 | `imds_ssrf` | Cloud IMDS SSRF | T1552.005 | ✓ | — | כן | Cloud metadata service exploitation: IMDSv1 SSRF credential theft, IMDSv2 hop-limit bypass, GCP meta |
| 35 | `k8s_container` | K8s Container | T1610 | ✓ | — | לא | Kubernetes RBAC misconfig, privileged pod escape, API server exposure |
| 36 | `kubernetes_rbac_escape` | Kubernetes RBAC Escape | T1610 | ✓ | — | כן | Kubernetes RBAC exploitation: over-permissive ClusterRole detection, service account token theft, et |
| 37 | `lambda_escape` | Lambda / Serverless Escape | T1610 | ✓ | — | כן | Serverless function exploitation: Lambda execution context persistence, function-to-function lateral |
| 38 | `lambda_layer_inject` | Lambda / Cloud Function Layer Inject | T1525 | ✓ | — | כן | Serverless function poisoning: Lambda layer dependency injection, Cloud Function environment variabl |
| 39 | `multi_cloud_pivot` | Multi-Cloud Pivot | T1552.005 | ✓ | — | לא | Cross-cloud lateral movement: AWS-to-GCP federation abuse, Azure Arc exploitation, cross-tenant OAut |
| 40 | `s3_bucket_attack` | S3 Bucket Misconfiguration Attack | T1530 | ✓ | — | לא | AWS S3 security exploitation: public bucket enumeration, ACL misconfiguration detection, bucket poli |
| 41 | `s3_bucket_enum` | Cloud Storage Bucket Takeover | T1530 | ✓ | — | כן | Cloud object storage exploitation: S3/GCS/Azure blob enumeration, subdomain takeover via unclaimed b |
| 42 | `secrets_manager_attack` | Cloud Secrets Manager Attack | T1555 | ✓ | — | לא | Cloud secrets management exploitation: AWS Secrets Manager enumeration, GCP Secret Manager access vi |
| 43 | `serverless_attack` | Serverless Attack | T1648 | ✓ | — | כן | Serverless event injection, function chaining, cold-start timing attacks |
| 44 | `serverless_cold_start` | Serverless Cold-Start Race | T1648 | ✓ | — | כן | Serverless race conditions: function cold-start shared-memory exploitation, concurrent invocation TO |
| 45 | `serverless_injection` | Serverless Function Injection | T1059 | ✓ | — | כן | Serverless injection attacks: Lambda/Function event data injection, environment variable poisoning,  |
| 46 | `service_mesh_attack` | Service Mesh Attack Engine | T1557 | ✓ | — | כן | Service mesh (Istio/Linkerd/Consul) exploitation: mTLS certificate theft, Envoy proxy SSRF, control  |
| 47 | `terraform_state_attack` | Terraform State File Exploiter | T1552 | ✓ | — | כן | Terraform state file exploitation: S3/GCS/Azure Blob state file secret extraction, state file inject |
| 48 | `terraform_state_steal` | Terraform State Exfiltration | T1552 | ✓ | — | כן | IaC state file attack: Terraform S3 backend credential extraction, Atlantis webhook hijacking, Terra |

### קריפטו וזהות (`crypto`) — 42 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `active_directory_cs` | AD Certificate Services Abuse | T1649 | ✓ | — | כן | ADCS ESC1-8 attack chain: misconfigured certificate templates, NTAuth store manipulation, shadow cre |
| 2 | `biometric_spoofing` | Biometric Bypass | T1556 | ✓ | — | לא | Biometric authentication bypass: 3D-printed fingerprint, IR face-liveness defeat, palm/iris presenta |
| 3 | `cold_boot_attack` | Cold Boot / DRAM Remanence Attack | T1552.004 | — | **חובה** | לא | RAM cold boot attack for cryptographic key extraction: DRAM remanence exploitation (memory data pers |
| 4 | `crypto_engine` | Crypto Engine | T1600 | ✓ | — | כן | Cipher suite analysis, padding oracle, ECB mode detection, entropy audit |
| 5 | `ecdsa_nonce_bias` | ECDSA Nonce Bias Attack | T1600 | ✓ | — | לא | ECDSA cryptographic attacks: nonce bias exploitation via LLL lattice reduction (Minerva/Hnonce attac |
| 6 | `email_dns_posture` | Email & Domain Trust Posture | T1566 | ✓ | — | כן | World-class anti-spoofing & DNS hardening audit — SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, DNSSEC,  |
| 7 | `golden_ticket` | Kerberos Golden / Silver Ticket | T1558.001 | ✓ | — | כן | Kerberos ticket forgery: Golden Ticket via KRBTGT hash, Silver Ticket for service impersonation, Dia |
| 8 | `hardware_wallet_attack` | Crypto Hardware Wallet Security Engine | T1552.004 | ✓ | — | לא | Hardware cryptocurrency wallet exploitation: Ledger/Trezor physical attack simulation, seed phrase e |
| 9 | `harvest_now_decrypt_later` | Harvest-Now Decrypt-Later (HNDL) Engine | T1040 | ✓ | — | כן | Long-term cryptographic threat modeling: identification of quantum-vulnerable encrypted traffic stre |
| 10 | `hash_extension_attack` | Hash Length Extension Attack | T1600 | ✓ | — | כן | Hash length extension exploitation: MD5/SHA1/SHA2 extension attacks against HMAC-like constructions, |
| 11 | `hsm_attack` | HSM Side-Channel / Fault Attack | T1552.004 | ✓ | — | לא | Hardware Security Module attack emulation: PKCS#11 key extraction via oracle, electromagnetic side-c |
| 12 | `jwt_attacks` | JWT / Token Attacks | T1552.001 | ✓ | — | כן | JWT algorithm confusion (RS256→HS256), none-alg bypass, weak secret brute-force, jwk injection, kid  |
| 13 | `kerberoasting` | Kerberoasting & AD External Posture | T1558.003 | ✓ | — | כן | Supreme-tier agentless AD/Kerberos posture: 18 live probe layers — DNS SRV/_msdcs auto-DC discovery, |
| 14 | `kerberos_attack_suite` | Kerberos Attack Suite | T1558 | ✓ | — | כן | Advanced Kerberos exploitation: Golden Ticket forgery simulation, Silver Ticket for service imperson |
| 15 | `key_derivation_flaw` | Weak Key Derivation Exploit | T1600 | ✓ | — | לא | KDF misconfiguration exploitation: low-iteration PBKDF2 cracking, bcrypt cost-1 rainbow table, Argon |
| 16 | `lattice_crypto_attack` | Lattice Cryptography Attack Engine | T1600 | ✓ | — | לא | Lattice-based cryptography weakness exploitation: LWE (Learning With Errors) parameter weakness anal |
| 17 | `mfa_bypass_engine` | MFA Bypass Engine | T1621 | ✓ | — | כן | Multi-factor authentication bypass: real-time phishing (Evilginx2/Modlishka relay), TOTP code phishi |
| 18 | `ntlm_relay` | NTLM Relay / Pass-the-Hash | T1557.001 | ✓ | — | כן | NTLM exploitation: Responder-based credential capture, SMB/HTTP NTLM relay to LDAP, Pass-the-Hash la |
| 19 | `oauth_abuse` | OAuth / OIDC Abuse | T1550.001 | ✓ | — | כן | OAuth/OIDC attack chain: authorization-code interception, implicit-flow token theft, state-param CSR |
| 20 | `oauth_advanced_attack` | OAuth 2.0 Advanced Attack Suite | T1550.001 | ✓ | — | כן | Comprehensive OAuth 2.0 attacks: authorization code interception, implicit flow token leakage, mix-u |
| 21 | `padding_oracle_attack` | Padding Oracle Attack | T1600 | ✓ | — | כן | CBC padding oracle exploitation: PKCS#7 padding oracle for AES-CBC decryption, ASP.NET ViewState MAC |
| 22 | `password_crack` | GPU Hash Cracking Engine | T1110.002 | ✓ | — | לא | Offline password hash cracking: Hashcat GPU-accelerated attack, rainbow table lookup, rule-based man |
| 23 | `password_hash_crack` | Password Hash Cracking Engine | T1110.002 | ✓ | — | לא | Password hash cracking simulation: NTLM/LM/NTLMv2 hash identification, bcrypt/Argon2/scrypt weakness |
| 24 | `password_spray` | Password Spray & Stuffing Posture | T1110.003 | ✓ | — | כן | Supreme-tier agentless credential intelligence: 22 live probe layers — Entra AADSTS, M365 GetUserRea |
| 25 | `password_spray_advanced` | Advanced Password Spray Engine | T1110.003 | ✓ | — | כן | Advanced password spraying: seasonality-aware password generation (Spring2024!, Welcome1), organizat |
| 26 | `pki_cert_forge` | PKI Certificate Forgery | T1553.004 | ✓ | — | כן | Certificate-based attack: rogue CA installation, MITM via forged leaf cert, CT log omission detectio |
| 27 | `pki_hierarchy_attack` | PKI Hierarchy Attack Engine | T1588.004 | ✓ | — | כן | PKI infrastructure attacks: AD CS (Active Directory Certificate Services) exploitation (ESC1-ESC8 te |
| 28 | `pki_tls` | PKI / TLS | T1557.002 | ✓ | — | כן | World-class TLS/PKI posture — live protocol matrix (SSLv3→TLS 1.3), exhaustive cipher enumeration, c |
| 29 | `pqc_implementation_attack` | Post-Quantum Cryptography Implementation Attack | T1600 | ✓ | — | לא | PQC algorithm implementation vulnerability analysis: CRYSTALS-Kyber timing side-channel (CVE-2023-33 |
| 30 | `pqc_scanner` | PQC Scanner | T1600 | ✓ | — | כן | Post-quantum readiness: RSA key size, algorithm inventory, NIST PQC gap |
| 31 | `quantum_attack` | Quantum Threat Emulation | T1600 | ✓ | — | כן | Source code secret scanning: hardcoded API keys, AWS credentials, JWT signing secrets in git history |
| 32 | `quantum_key_attack` | Quantum Computing Key Attack Simulator | T1600 | ✓ | — | לא | Quantum-era cryptographic risk assessment: Shor\ |
| 33 | `rsa_timing_attack` | RSA Timing Side-Channel | T1600 | ✓ | — | כן | RSA implementation timing attacks: Kocher timing attack on RSA-CRT, Bleichenbacher PKCS#1 v1.5 oracl |
| 34 | `saml_advanced_attack` | SAML Advanced Attack Engine | T1606.002 | ✓ | — | כן | Advanced SAML exploitation: XML signature wrapping (XSW) attacks 1-8, SAML assertion replay, NameID  |
| 35 | `saml_attack` | SAML Attack & SSO Federation | T1550.004 | ✓ | — | כן | Supreme-tier agentless SAML/WS-Fed posture: metadata X.509 parse, RelayState canary, unsigned assert |
| 36 | `session_fixation_adv` | Advanced Session Fixation | T1563 | ✓ | — | כן | Advanced session attacks: session fixation via URL parameter/cookie injection, session puzzling/over |
| 37 | `side_channel` | Side-Channel Attack | T1600 | ✓ | — | לא | Timing side-channels on crypto primitives, cache-timing (Flush+Reload), speculative execution leakag |
| 38 | `tls_downgrade` | TLS / SSL Downgrade Attack | T1600.001 | ✓ | — | כן | Protocol downgrade exploitation: BEAST, POODLE (SSLv3/TLS1.0), DROWN (SSLv2), FREAK (export cipher), |
| 39 | `totp_bruteforce` | TOTP / MFA Brute Force | T1110 | ✓ | — | כן | Multi-factor authentication attacks: TOTP timing window brute force, OTP SMS interception via SS7, M |
| 40 | `tpm_firmware_attack` | TPM Firmware Attack Engine | T1600 | — | **חובה** | לא | Trusted Platform Module exploitation: TPM 1.2/2.0 bus sniffing for key extraction (CVE-2018-6622 pat |
| 41 | `voltage_glitch_attack` | Voltage / Clock Glitch Fault Injection | T1600 | — | **חובה** | לא | Hardware fault injection via voltage/clock glitching: secure boot bypass by glitching signature veri |
| 42 | `webauthn_fido2_bypass` | WebAuthn / FIDO2 Bypass Engine | T1621 | ✓ | — | כן | WebAuthn/FIDO2 passkey security exploitation: authenticator emulation via virtual FIDO2 device, cred |

### דליפת מידע (`data`) — 15 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `acoustic_exfil` | Acoustic Side-Channel Exfiltration | T1048 | — | **חובה** | לא | Acoustic covert channel attacks: CPU fan speed modulation for data exfiltration, hard drive acoustic |
| 2 | `cache_timing_exfil` | CPU Cache Side-Channel Exfiltration | T1048 | ✓ | — | לא | CPU cache-based covert channels: Flush+Reload cross-VM exfiltration, Prime+Probe cache attack, Spect |
| 3 | `clipboard_hijack` | Clipboard Hijacking Engine | T1115 | — | **חובה** | לא | Clipboard-based attacks: cryptocurrency address replacement (clipper malware), clipboard monitoring  |
| 4 | `cloud_exfil_engine` | Cloud Storage Exfiltration Engine | T1567.002 | ✓ | — | לא | Cloud-based exfiltration channels: S3/GCS/Azure Blob unauthorized data staging, OneDrive/SharePoint  |
| 5 | `database_exfil` | Database Exfiltration Engine | T1048 | ✓ | — | כן | Database exfiltration techniques: SQL injection to direct exfiltration, MySQL OUTFILE/LOAD_INFILE ex |
| 6 | `dns_exfil_engine` | DNS Exfiltration Engine | T1048.003 | ✓ | — | כן | DNS-based data exfiltration: base64/hex encoding in DNS queries, DNSCAT2-style exfiltration simulati |
| 7 | `em_exfil_engine` | Electromagnetic Emanation Exfiltration | T1048 | — | **חובה** | לא | Electromagnetic covert channel attacks: TEMPEST van Eck phreaking simulation, AirHopper GPU radio tr |
| 8 | `email_exfil` | Email-Based Exfiltration Engine | T1048.003 | ✓ | — | כן | Email covert channel exfiltration: SMTP-based data encoding in headers/body, Office 365/Exchange SMT |
| 9 | `encrypted_exfil` | Encrypted Covert Exfiltration | T1048.002 | ✓ | — | כן | Encrypted exfiltration channel creation: custom protocol over TLS, steganographic exfil in image/vid |
| 10 | `http_covert_exfil` | HTTP Covert Channel Exfiltration | T1048.003 | ✓ | — | כן | HTTP-based covert exfiltration: data encoded in HTTP headers (Cookie, Referer, User-Agent), chunked  |
| 11 | `insider_exfil` | Insider Threat Exfiltration Engine | T1048 | — | **חובה** | לא | Insider threat exfiltration simulation: DLP bypass techniques, printing to PDF for exfil, screenshot |
| 12 | `keyboard_acoustic` | Keyboard Acoustic Eavesdropping | T1056.001 | — | **חובה** | לא | Acoustic keyboard eavesdropping: keystroke timing analysis for password inference, spectrogram-based |
| 13 | `optical_exfil` | Optical Covert Channel Exfiltration | T1048 | — | **חובה** | לא | Optical covert channel attacks: LED-based data exfiltration (aIR-Jumper via security camera IR LEDs) |
| 14 | `screen_capture_exfil` | Screen Capture Exfiltration Engine | T1113 | — | **חובה** | לא | Screen capture-based exfiltration: periodic screenshot for data harvest, video recording via DXGI du |
| 15 | `storage_covert_channel` | Storage Covert Channel Engine | T1048 | — | **חובה** | לא | Storage-based covert channels: NTFS alternate data stream (ADS) exfiltration, file system metadata c |

### Malware ו-Ransomware (`malware`) — 14 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `bootkit_uefi` | UEFI/Bootkit Implant Detector | T1542.001 | — | **חובה** | לא | UEFI and bootkit security analysis: Secure Boot bypass detection, BootHole (GRUB2 CVE-2020-10713) si |
| 2 | `botnet_c2_engine` | Botnet C2 Infrastructure Engine | T1102 | ✓ | — | לא | Botnet command and control: DGA (Domain Generation Algorithm) simulation, P2P botnet architecture an |
| 3 | `data_staging_engine` | Data Staging Engine | T1074 | ✓ | — | לא | Pre-exfiltration data staging: sensitive file discovery (credential files, databases, documents), ar |
| 4 | `exploit_kit_engine` | Exploit Kit Simulation Engine | T1203 | ✓ | — | כן | Browser exploit kit simulation: drive-by download via malicious redirects, exploit kit landing page  |
| 5 | `fileless_malware_engine` | Fileless Malware Engine | T1055 | ✓ | — | לא | Fileless attack techniques: PowerShell in-memory execution, process injection without disk writes, r |
| 6 | `keylogger_engine` | Keylogger Engine | T1056.001 | ✓ | — | לא | Keylogger implementation analysis: Windows SetWindowsHookEx API-based hooking, kernel-level filter d |
| 7 | `lateral_movement_engine` | Lateral Movement Engine | T1021 | ✓ | — | לא | Lateral movement technique simulation: Pass-the-Hash (PtH), Pass-the-Ticket (PtT), Overpass-the-Hash |
| 8 | `macro_malware` | Office Macro Malware Engine | T1566.001 | ✓ | — | לא | Malicious Office macro analysis: VBA stomping detection, Excel 4.0 macro exploitation (XLM), Remote  |
| 9 | `persistence_mechanism` | Persistence Mechanism Engine | T1547 | — | **חובה** | לא | Persistence technique comprehensive coverage: Windows Registry Run keys, WMI event subscriptions, sc |
| 10 | `polymorphic_engine` | Polymorphic Code Engine | T1027.001 | — | **חובה** | לא | Polymorphic malware simulation: code mutation while preserving functionality, metamorphic code trans |
| 11 | `rce_exploit_engine` | Remote Code Execution Exploit Engine | T1190 | ✓ | — | כן | RCE vulnerability exploitation: Log4Shell (CVE-2021-44228) detection and exploitation, Spring4Shell  |
| 12 | `spyware_stalkerware` | Spyware/Stalkerware Engine | T1429 | ✓ | — | לא | Spyware technique analysis: mobile device location tracking, call/SMS interception, microphone/camer |
| 13 | `trojan_dropper` | Trojan Dropper Engine | T1027.006 | ✓ | — | לא | Trojan dropper technique analysis: embedded payload extraction, self-deleting dropper, loader stage  |
| 14 | `worm_propagation` | Network Worm Propagation Engine | T1210 | ✓ | — | לא | Network worm propagation simulation: vulnerability scanning for auto-spread, EternalBlue/EternalRoma |

### מובייל (`mobile`) — 15 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `android_intent_attack` | Android Intent Hijacking Engine | T1417 | ✓ | — | כן | Android inter-component communication attacks: implicit intent hijacking, exported activity/receiver |
| 2 | `android_malware_engine` | Android Malware Analysis Engine | T1407 | ✓ | — | לא | Android malware behavior analysis: APK static analysis for malicious permissions, dynamic analysis v |
| 3 | `app_store_attack` | App Store Attack Engine | T1475 | ✓ | — | לא | App store supply chain attacks: malicious SDK injection detection (Goldoson/XcodeGhost/AXLoader), ap |
| 4 | `bluetooth_mobile_attack` | Mobile Bluetooth Attack Engine | T1011.001 | — | **חובה** | לא | Mobile Bluetooth exploitation: BLE MITM via key extraction (Method confusion attack), Bluetooth Impe |
| 5 | `ios_exploit_engine` | iOS Exploitation Engine | T1404 | ✓ | — | לא | iOS security exploitation: kernel exploit chain detection (WebKit+Sandbox+kernel), jailbreak detecti |
| 6 | `ios_url_scheme_attack` | iOS URL Scheme Attack Engine | T1417 | ✓ | — | כן | iOS URL scheme exploitation: custom URL scheme hijacking for OAuth token theft, scheme flooding (CVE |
| 7 | `mdm_bypass_engine` | MDM/EMM Bypass Engine | T1407 | ✓ | — | לא | Mobile Device Management bypass: MDM enrollment circumvention, device compliance check bypass, Jamf/ |
| 8 | `mobile_banking_trojan` | Mobile Banking Trojan Engine | T1417 | ✓ | — | לא | Mobile banking trojan technique analysis: overlay banking attack (Anubis/Cerberus/Hydra patterns), U |
| 9 | `mobile_mitm` | Mobile MITM Attack Engine | T1557 | ✓ | — | לא | Mobile man-in-the-middle attacks: rogue hotspot creation, certificate pinning bypass via Frida/objec |
| 10 | `mobile_overlay_attack` | Mobile Overlay Attack Engine | T1417 | ✓ | — | לא | Mobile UI overlay attacks: Android tapjacking (clickjacking for touch), translucent overlay phishing |
| 11 | `mobile_spyware_engine` | Mobile Spyware Engine | T1429 | ✓ | — | לא | Commercial spyware analysis: Pegasus NSO Group-style zero-click exploit indicators, FinFisher/FinSpy |
| 12 | `nfc_relay_attack` | NFC Relay Attack Engine | T1606 | — | **חובה** | לא | NFC security attacks: contactless payment relay attack via two Android devices, NFC cloning simulati |
| 13 | `react_native_attack` | React Native / Flutter App Attack | T1417 | ✓ | — | כן | Cross-platform mobile app exploitation: React Native JS bundle extraction and modification, Flutter  |
| 14 | `sim_swap_engine` | SIM Swap Attack Engine | T1621 | — | **חובה** | לא | SIM swapping attack simulation: carrier social engineering scripts, SS7-based SIM swap, eSIM exploit |
| 15 | `ssl_pinning_bypass` | SSL Pinning Bypass Engine | T1521.001 | ✓ | — | כן | SSL certificate pinning bypass: Frida-based dynamic pinning bypass, OkHttp/Retrofit pinning removal, |

### רשת ופרוטוקולים (`network`) — 54 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `5g_security` | 5G / Cellular Security | T1040 | ✓ | — | לא | Cellular network assessment: IMSI catcher simulation, NAS signaling fuzzing, GTP-U tunnel hijacking, |
| 2 | `arp_spoofing` | ARP Spoofing / LAN MITM | T1557.002 | ✓ | — | כן | Layer-2 man-in-the-middle: ARP cache poisoning, gratuitous ARP flooding, DHCP spoofing, IPv6 router  |
| 3 | `arp_spoofing_engine` | ARP Spoofing / Cache Poisoning | T1557.002 | — | **חובה** | כן | ARP-based MITM attacks: ARP cache poisoning simulation, gratuitous ARP flooding, ARP spoofing for cr |
| 4 | `bgp_dns_hijacking` | DNS & Domain Posture | T1584.005 | ✓ | — | כן | Agentless DNS/domain posture: multi-resolver integrity, DNSSEC, SPF/DKIM/DMARC/MTA-STS email-auth, C |
| 5 | `bgp_hijacking` | BGP Route Hijacking | T1584.005 | ✓ | — | לא | BGP prefix hijack simulation, RPKI validation bypass, route leak detection, AS-path poisoning, BGP s |
| 6 | `bluetooth_attack` | Bluetooth / BLE Attack | T1011.001 | ✓ | — | לא | Bluetooth and BLE attack suite: BLESA spoofing, BIAS authentication bypass, BLE MITM, HID injection, |
| 7 | `bluetooth_attack_engine` | Bluetooth Attack Engine | T1011.001 | — | **חובה** | לא | Bluetooth security exploitation: BLE GATT attribute enumeration, BlueBorne vulnerability simulation, |
| 8 | `dhcp_attack_engine` | DHCP Starvation & Rogue Server | T1557 | — | **חובה** | כן | DHCP protocol attacks: DHCP starvation via MAC flooding, rogue DHCP server for gateway redirect, DHC |
| 9 | `dhcp_starvation` | DHCP Starvation / Rogue Server | T1557 | ✓ | — | כן | DHCP-based attacks: starvation via MAC flooding, rogue DHCP server for default gateway redirect, DHC |
| 10 | `dns_cache_poisoning` | DNS Cache Poisoning Engine | T1584.002 | ✓ | — | כן | DNS cache poisoning attacks: Kaminsky-style off-path attack simulation, birthday paradox-based poiso |
| 11 | `dns_rebinding` | DNS Rebinding | T1557 | ✓ | — | כן | Same-origin policy bypass via DNS rebind, intranet pivot, browser-as-proxy, rebind-SSRF chaining |
| 12 | `dns_tunneling` | DNS Tunneling C2 | T1071.004 | ✓ | — | כן | DNS-based C2 and exfiltration: Iodine/dnscat2 protocol emulation, low-and-slow DNS beacon, TXT/NULL/ |
| 13 | `icmp_covert_channel` | ICMP / DNS Covert Channel | T1095 | ✓ | — | לא | Protocol-tunneled exfiltration: ICMP echo payload C2, DNS TXT/NULL record tunneling (dnscat2), HTTP  |
| 14 | `ipsec_vpn_audit` | IPSec / VPN Audit | T1133 | ✓ | — | כן | VPN configuration audit: IKEv1/v2 aggressive-mode fingerprint, weak cipher enumeration, split-tunnel |
| 15 | `ipv6_advanced_attack` | IPv6 Advanced Attack Engine | T1590.004 | ✓ | — | כן | IPv6 security exploitation: SLAAC-based address prediction, NDP (Neighbor Discovery Protocol) spoofi |
| 16 | `ipv6_attack` | IPv6 Attack | T1018 | ✓ | — | כן | AAAA record enumeration, link-local leak detection, IPv6 RA flood surface |
| 17 | `lateral_movement` | Lateral Movement | T1021 | ✓ | — | כן | WMI/DCOM, PsExec, SSH key reuse, RDP hijacking, token impersonation, credential re-spray |
| 18 | `ldap_injection` | LDAP / AD Injection | T1078.002 | ✓ | — | כן | LDAP injection for authentication bypass, directory enumeration, AD attribute harvesting, Kerberoast |
| 19 | `ldap_injection_engine` | LDAP Injection Engine | T1190 | ✓ | — | כן | LDAP injection exploitation: blind LDAP injection via boolean conditions, authentication bypass via  |
| 20 | `lte_5g_attack` | LTE/5G Network Attack Engine | T1557 | — | **חובה** | לא | 4G/5G mobile network attacks: IMSI catcher simulation (false base station), LTE rogue eNB detection  |
| 21 | `mpls_vpn_attack` | MPLS/VPN Network Attack | T1599 | ✓ | — | לא | MPLS network exploitation: VPN label spoofing, inter-VRF route leakage, MPLS label stack manipulatio |
| 22 | `mtls_grpc` | Transport Security (TLS/mTLS/gRPC) | T1557 | ✓ | — | כן | World-class agentless transport posture — weak-crypto matrix, gRPC/gRPC-Web/Connect-RPC, mTLS, HSTS/ |
| 23 | `multicast_attack` | Multicast Protocol Attack Engine | T1557 | — | **חובה** | לא | IP multicast protocol attacks: IGMP snooping bypass, PIM-SM join/prune manipulation, multicast routi |
| 24 | `nat_traversal_attack` | NAT Traversal Attack Engine | T1090 | — | **חובה** | כן | NAT security bypass: STUN/TURN protocol exploitation for NAT traversal, NAT punching for covert C2,  |
| 25 | `network_baseline_anomaly` | Network Baseline Anomaly Engine | T1040 | ✓ | — | כן | Network behavior baseline anomaly detection: statistical deviation from normal traffic patterns, new |
| 26 | `network_covert_channel` | Network Covert Channel Engine | T1095 | ✓ | — | כן | Network protocol covert channels: TCP/IP header field-based exfiltration (TTL, ID field, sequence nu |
| 27 | `network_slice_isolation_bypass` | 5G Network Slice Isolation Bypass | T1190 | ✓ | — | לא | 5G network slicing security bypass: slice isolation policy violation, cross-slice resource exhaustio |
| 28 | `network_tap_advanced` | Advanced Network TAP/SPAN Engine | T1557 | — | **חובה** | כן | Advanced network interception: SPAN port misconfiguration detection, RSPAN/ERSPAN covert tap, optica |
| 29 | `network_tap_implant` | Network TAP / SPAN Implant | T1557 | ✓ | — | לא | Passive network interception emulation: SPAN port misconfiguration, VLAN tapping, ARP poisoning for  |
| 30 | `nfv_mano_attack` | NFV MANO / VNF Exploitation | T1610 | ✓ | — | לא | Network Function Virtualization MANO exploitation: NFVO (Network Functions Virtualization Orchestrat |
| 31 | `ntp_amplification` | NTP / UDP Amplification DDoS | T1498.002 | ✓ | — | לא | Reflection/amplification DDoS emulation: NTP monlist (600x amplification), DNS ANY amplification, me |
| 32 | `ospf_bgp_hijack` | OSPF/BGP Route Hijacking | T1557 | ✓ | — | לא | Routing protocol attacks: BGP prefix hijacking simulation, OSPF type 1 LSA injection, BGP AS path ma |
| 33 | `ospf_bgp_manipulation` | OSPF / BGP Route Manipulation | T1557 | ✓ | — | כן | Routing protocol exploitation: OSPF LSA injection for traffic redirection, BGP route hijacking via A |
| 34 | `packet_injection_engine` | Packet Injection Engine | T1557 | — | **חובה** | כן | Raw packet injection attacks: TCP RST injection for session termination, BGP UPDATE injection via MI |
| 35 | `protocol_downgrade` | Protocol Downgrade Engine | T1600.001 | ✓ | — | כן | Cryptographic protocol downgrade attacks: TLS version downgrade (POODLE/DROWN/FREAK), SSH version 1  |
| 36 | `rdp_attack_engine` | RDP Attack Engine | T1021.001 | ✓ | — | כן | Remote Desktop Protocol exploitation: BlueKeep (CVE-2019-0708) check, DejaBlue variant detection, RD |
| 37 | `rdp_exploit` | RDP Exploitation Engine | T1021.001 | ✓ | — | כן | Remote Desktop Protocol exploitation: BlueKeep (CVE-2019-0708), DejaBlue, RDP credential brute force |
| 38 | `sase_security_bypass` | SASE / SSE Security Bypass Engine | T1562 | ✓ | — | כן | SASE (Secure Access Service Edge) and SSE bypass: Zscaler/Netskope/Palo Alto Prisma tunnel bypass vi |
| 39 | `satellite_attack` | Satellite / Space Security | T1498 | ✓ | — | לא | Satellite link interception, GPS spoofing, Starlink dish exploitation, ground station protocol fuzzi |
| 40 | `sdn_controller_exploit` | SDN Controller Exploitation Engine | T1498 | ✓ | — | כן | Software-Defined Networking controller exploitation: OpenDaylight REST API authentication bypass, ON |
| 41 | `smb_netbios` | SMB / NetBIOS | T1021.002 | ✓ | — | כן | Live SMB2/3 negotiation: signing & encryption posture, SMBv1/EternalBlue & SMBGhost, MS17-010 Trans2 |
| 42 | `smb_relay` | SMB / NTLM Relay | T1557.001 | ✓ | — | כן | SMB/NTLM relay attacks: NTLMv2 capture, relay-to-LDAP/SMB/HTTP, ADCS ESC8, shadow-credential injecti |
| 43 | `snmp_attack` | SNMP Community String Attack | T1040 | ✓ | — | כן | SNMP exploitation: community string brute force, SNMPv1/v2c write-community device reconfiguration,  |
| 44 | `snmp_exploitation` | SNMP Community Exploitation | T1602.001 | ✓ | — | כן | SNMP security exploitation: community string brute force (public/private/community), SNMPv1/v2c writ |
| 45 | `ss7_attack_simulation` | SS7 Telecom Protocol Attack | T1557 | ✓ | — | לא | SS7 signaling protocol exploitation simulation: SMS interception via HLR/VLR query spoofing, call fo |
| 46 | `telco_ss7_attack` | Telecom / SS7 Attack | T1040 | ✓ | — | לא | SS7/Diameter/GTP protocol attack emulation: SMS interception, call forwarding hijacking, IMSI tracki |
| 47 | `tor_exit_attack` | Tor Exit Node Attack Engine | T1090.003 | ✓ | — | לא | Tor network exploitation: exit node SSL stripping, traffic correlation attacks, onion service deanon |
| 48 | `vlan_bypass` | VLAN Bypass | T1599 | ✓ | — | כן | VLAN double-tagging (802.1Q/802.1ad), DTP trunk negotiation, native VLAN abuse, inter-VLAN pivot and |
| 49 | `vlan_hopping_attack` | VLAN Hopping Attack Engine | T1016 | — | **חובה** | כן | VLAN security bypass: double tagging attack (802.1Q), switch spoofing via DTP negotiation, native VL |
| 50 | `voip_sip_attack` | VoIP / SIP Protocol Attack | T1040 | ✓ | — | כן | VoIP security exploitation: SIP REGISTER hijacking, call interception via RTP injection, SIP digest  |
| 51 | `wifi_attack` | Wi-Fi / 802.11 Attack Suite | T1491 | ✓ | — | לא | Wireless LAN attacks: WPA2/WPA3 PMKID capture, PMKID cracking, deauth/disassoc flooding, evil twin A |
| 52 | `wifi_attack_engine` | WiFi Attack Suite | T1557.003 | — | **חובה** | לא | WiFi security exploitation: WPA3 Dragonblood side-channel attacks, PMKID offline attack, DEAUTH beac |
| 53 | `wireless_attack` | Wireless Attack | T1465 | ✓ | — | לא | WiFi PMKID cracking, 802.11 deauth flood, evil-twin AP, KRACK replay, WPA2 handshake capture |
| 54 | `wpa3_attack_engine` | WPA3/WiFi 6E Attack Engine | T1557.003 | — | **חובה** | לא | Advanced WiFi security attacks: WPA3-SAE Dragonblood timing/cache side-channel, WPA3-Enterprise EAP  |

### OT / ICS / IoT (`ot`) — 32 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `automotive_can_bus` | Automotive / CAN Bus Attack | T1498 | ✓ | — | לא | CAN bus frame injection, ECU firmware extraction, OBD-II exploit surface, V2X protocol fuzzing, OTA  |
| 2 | `bacnet_attack` | BACnet Building Automation Attack | T0830 | ✓ | — | כן | BACnet/IP exploitation: unauthenticated device enumeration, HVAC setpoint manipulation, fire alarm s |
| 3 | `ble_rf` | Wireless & RF IoT Posture | T1011 | ✓ | — | כן | Agentless wireless/IoT perimeter assessment — IoT cloud hubs (AWS/Azure/GCP/Home Assistant), BLE/GAT |
| 4 | `can_fd_attack` | CAN / CAN FD Bus Attack | T0838 | ✓ | — | לא | Automotive CAN bus exploitation: UDS diagnostic command injection, ECU firmware spoofing, DoS via er |
| 5 | `coap_attack` | CoAP Protocol Exploitation | T0836 | ✓ | — | כן | CoAP IoT protocol attacks: resource discovery enumeration, observe option flooding, amplification DD |
| 6 | `dnp3_attack` | DNP3 Protocol Attack | T0855 | ✓ | — | כן | DNP3 attack emulation: unsolicited response injection, application layer auth bypass, master station |
| 7 | `firmware_emulation` | Firmware Emulation | T1542 | ✓ | — | לא | Firmware extraction and QEMU-based emulation: hardcoded credential extraction, debug interface disco |
| 8 | `firmware_emulation_attack` | IoT Firmware Emulation Attack | T1542 | ✓ | — | לא | IoT firmware security analysis: QEMU/FIRMADYNE-based firmware emulation, hardcoded credential extrac |
| 9 | `firmware_exploit` | Firmware Exploit | T1542.001 | ✓ | — | כן | UART/JTAG boot extraction, secure-boot bypass, bootloader signature spoofing, OTA update hijacking |
| 10 | `hardware_implant` | Hardware Implant / Supply Chain | T1195.003 | ✓ | — | לא | Hardware supply chain attack emulation: PCB-level implant detection, JTAG/SWD debug port enumeration |
| 11 | `hmi_attack` | HMI/SCADA UI Attack Engine | T0836 | ✓ | — | כן | HMI exploitation: WinCC/FactoryTalk/Wonderware web interface attacks, SQL injection in historian, cr |
| 12 | `hmi_exploit` | HMI / SCADA Interface Exploit | T0817 | ✓ | — | כן | HMI software exploitation: Inductive Automation Ignition RCE, Wonderware thin client path traversal, |
| 13 | `hospital_hl7_attack` | HL7 / DICOM Healthcare Protocol Attack | T0826 | ✓ | — | כן | Healthcare-specific protocol attacks: HL7 v2/v3/FHIR REST API injection for patient data manipulatio |
| 14 | `ics_historian_attack` | ICS Historian Database Attack | T0832 | ✓ | — | כן | ICS historian exploitation: OSIsoft PI SQL injection, Aspentech IP.21 credential brute force, histor |
| 15 | `iec61850_attack` | IEC 61850 GOOSE / SV Spoofing | T0856 | ✓ | — | כן | IEC 61850 protocol exploitation: GOOSE message injection and spoofing, sampled value (SV) replay, MM |
| 16 | `implantable_device_hack` | Implantable Medical Device Attack | T0826 | ✓ | — | לא | Implantable medical device (IMD) security: cardiac pacemaker/ICD RF attack simulation, insulin pump  |
| 17 | `industrial_protocol_fuzz` | Industrial Protocol Fuzzer | T0836 | ✓ | — | כן | Comprehensive ICS/OT protocol fuzzing: grammar-based fuzzing for Modbus/DNP3/IEC104/EtherNet-IP/PROF |
| 18 | `iot_firmware` | IoT Firmware | T1542 | ✓ | — | כן | Firmware extraction, hardcoded credential detection, update stream hijacking |
| 19 | `jtag_swd_exploitation` | JTAG/SWD Debug Interface Exploiter | T1542 | ✓ | — | לא | Hardware debug interface exploitation: JTAG/SWD port discovery on PCBs, boundary scan for chip ident |
| 20 | `lorawan_attack` | LoRaWAN IoT Network Attack | T0860 | — | **חובה** | לא | LoRaWAN exploitation: join request replay, devNonce brute force, bit-flipping attack on encrypted pa |
| 21 | `medical_device_exploit` | Medical IoT Device Exploit Engine | T0826 | ✓ | — | כן | FDA-regulated medical device exploitation: infusion pump command injection over network (Alaris/Baxt |
| 22 | `modbus_attack` | Modbus Protocol Attack | T0836 | ✓ | — | כן | Modbus industrial protocol exploitation: function code enumeration, coil/register read/write, device |
| 23 | `modbus_exploit` | Modbus TCP Exploitation | T0836 | ✓ | — | כן | Modbus TCP/RTU attack emulation: unauthenticated register read/write, coil manipulation, forced exce |
| 24 | `mqtt_attack` | MQTT Broker Attack Engine | T0836 | ✓ | — | כן | MQTT IoT protocol exploitation: anonymous authentication abuse, topic ACL bypass, message injection  |
| 25 | `opcua_attack` | OPC-UA Industrial Attack | T0836 | ✓ | — | כן | OPC Unified Architecture exploitation: anonymous endpoint access, security policy downgrade (None mo |
| 26 | `plc_logic_attack` | PLC Ladder Logic Attack | T0836 | ✓ | — | כן | PLC programming exploitation: ladder logic upload/download via exposed ports, Stuxnet-style function |
| 27 | `plc_logic_bomb` | PLC Logic Bomb Injection | T0873 | ✓ | — | כן | PLC program manipulation: Stuxnet-style ladder logic injection, time-triggered sabotage routine, saf |
| 28 | `profinet_attack` | PROFINET Industrial Attack | T0836 | ✓ | — | כן | PROFINET industrial Ethernet attacks: DCP device enumeration and spoofing, PROFINET RT frame injecti |
| 29 | `rfid_nfc_attack` | RFID/NFC Cloning Engine | T1606 | ✓ | — | לא | RFID and NFC security attacks: Mifare Classic key cracking (nested/hardnested), access card cloning  |
| 30 | `satellite_comm_attack` | Satellite Communication Attack | T0836 | ✓ | — | לא | Satellite communication security: DVB-S2 signal interception and decryption, VSAT terminal exploitat |
| 31 | `scada_ics` | SCADA / ICS | T0855 | ✓ | — | כן | Modbus, DNP3, IEC 61850 protocol fuzzing and unauthorized command detection |
| 32 | `zigbee_attack` | Zigbee Protocol Attack | T0860 | ✓ | — | לא | Zigbee security exploitation: network key extraction via commissioning sniff, replay attack, coordin |

### מודיעין ו-Recon (`recon`) — 42 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `active_directory_enum` | Active Directory Enum | T1087.002 | ✓ | — | כן | BloodHound-style AD attack-path mapping: ACL abuse, DCSync simulation, delegation misconfig, AdminSD |
| 2 | `adversarial_simulation` | Full Adversarial Simulation Engine | T1591 | ✓ | — | כן | End-to-end adversarial simulation: automated kill chain execution from recon to exfiltration, MITRE  |
| 3 | `asm` | Attack Surface Management | T1595 | ✓ | — | כן | External Attack Surface Management (EASM): asset discovery (CT + DNS brute), service/port exposure,  |
| 4 | `attack_graph_traversal` | Dynamic Attack Graph Traversal Engine | T1595 | ✓ | — | כן | Real-time attack graph construction and traversal: asset relationship graph from OSINT + active scan |
| 5 | `attack_surface_quantify` | Attack Surface Quantification | T1595 | ✓ | — | כן | Quantitative attack surface measurement: asset criticality scoring via CVSS/EPSS, exploitability pro |
| 6 | `blockchain_trace` | Blockchain Transaction Tracer | T1583.006 | ✓ | — | לא | Blockchain forensics and OSINT: Bitcoin/Ethereum transaction graph analysis, mixer detection, ransom |
| 7 | `cert_transparency` | Certificate Transparency Mining | T1596.003 | ✓ | — | כן | CT log enumeration for subdomain discovery, SAN certificate mapping, historical certificate pivoting |
| 8 | `compliance_gap_scan` | Compliance Gap Scanner | T1592 | ✓ | — | כן | Automated compliance gap analysis: PCI-DSS, HIPAA, SOC2, ISO 27001, GDPR control mapping against dis |
| 9 | `dark_web_monitor` | Dark Web Brand Monitor | T1597 | ✓ | — | כן | Comprehensive dark web brand monitoring: Tor marketplace credential listing detection, ransomware le |
| 10 | `darkweb_intel` | Dark Web Intelligence | T1597 | ✓ | — | כן | Comprehensive dark web monitoring: Tor hidden service enumeration, paste site scraping, underground  |
| 11 | `data_deanonymization` | Data De-anonymization Engine | T1592 | ✓ | — | כן | Advanced data re-identification and de-anonymization: quasi-identifier linkage attack (name+zip+DOB  |
| 12 | `deepweb_intel` | Dark / Deep Web Intelligence | T1597 | ✓ | — | לא | Automated dark-web intelligence gathering: Tor hidden service enumeration, paste-site credential mon |
| 13 | `differential_privacy_exploit` | Differential Privacy Implementation Attack | T1600 | ✓ | — | כן | Differential privacy (DP) vulnerability exploitation: privacy budget (ε) exhaustion via repeated que |
| 14 | `discovery_engine` | Discovery Engine | T1046 | ✓ | — | כן | Automated service and endpoint discovery via passive and active probing |
| 15 | `dns_enum` | DNS Zone Enumeration | T1590.002 | ✓ | — | כן | Full DNS enumeration: AXFR/IXFR zone transfer, brute-force subdomain discovery, NSEC3 walking, wildc |
| 16 | `email_harvest` | Email Address Harvester | T1589.002 | ✓ | — | כן | Automated email harvesting from OSINT sources: Hunter.io, Phonebook.cz, breach databases, corporate  |
| 17 | `email_spoofing` | Email Spoofing / DMARC Bypass | T1566.001 | ✓ | — | כן | Email authentication bypass: SPF/DKIM/DMARC misconfiguration, homoglyph lookalike domains, display-n |
| 18 | `employee_profiling` | Employee Profiling Engine | T1589.003 | ✓ | — | כן | Deep corporate employee profiling: role/title enumeration, technical stack inference from job posts, |
| 19 | `external_exposure_supreme` | External Exposure Supreme | T1595 | ✓ | — | כן | Live fusion of ASM + email/DNS posture + cloud posture with toxic-combination attack-path synthesis  |
| 20 | `financial_osint` | Financial OSINT Engine | T1591.002 | ✓ | — | כן | Financial intelligence gathering: SEC EDGAR filing analysis, corporate ownership graph tracing, bene |
| 21 | `geoint` | Geospatial Intelligence (GEOINT) | T1591 | ✓ | — | לא | Geospatial OSINT: EXIF GPS extraction from public images, satellite imagery analysis, datacenter loc |
| 22 | `github_recon` | GitHub / GitLab OSINT | T1593.003 | ✓ | — | כן | Code repository intelligence: GitHub org member enumeration, hardcoded secret discovery in public co |
| 23 | `github_secret_scan` | GitHub Secret Scanner | T1552.001 | ✓ | — | כן | Deep GitHub secret scanning: API key pattern matching (AWS, GCP, Azure, Stripe, Twilio), private key |
| 24 | `iot_shodan_scan` | IoT/ICS Shodan Deep Scan | T1595.001 | ✓ | — | לא | Targeted IoT/ICS scanning via Shodan/Censys/Fofa/ZoomEye: industrial protocol detection (Modbus, DNP |
| 25 | `job_posting_osint` | Job Posting Tech Stack OSINT | T1591.004 | ✓ | — | כן | Technology stack inference from job postings: LinkedIn/Indeed/Glassdoor scraping, software version i |
| 26 | `leak_hunter` | Leak Hunter | T1530 | ✓ | — | כן | Dark web & paste-site credential and data leak detection |
| 27 | `location_pattern_analysis` | Location Pattern De-anonymization Engine | T1591 | ✓ | — | לא | Location data analysis for target identification: mobile location dataset re-identification (4 spati |
| 28 | `metadata_harvest` | Document Metadata Harvester | T1592.002 | ✓ | — | כן | Document metadata extraction and analysis: PDF/Office author/editor enumeration, GPS EXIF from image |
| 29 | `mobile_attack` | Mobile Attack | T1421 | ✓ | — | כן | APK reversing, iOS plist credential leak, deep-link hijacking, MDM bypass, mobile OAuth PKCE theft |
| 30 | `network_topology_map` | Passive Network Topology Mapper | T1590.004 | ✓ | — | כן | Passive network topology reconstruction: BGP route analysis, traceroute-based path mapping, ISP peer |
| 31 | `passive_dns_forensics` | Passive DNS Forensics Engine | T1590.002 | ✓ | — | כן | Passive DNS intelligence: historical DNS resolution correlation, malicious domain fast-flux detectio |
| 32 | `patent_recon` | Patent & IP Intelligence | T1591 | ✓ | — | כן | Patent database OSINT: USPTO/EPO filing analysis for technology stack inference, inventor/employee i |
| 33 | `recon` | Recon & OSINT | T1589 | ✓ | — | כן | Open-source intelligence gathering across all public data sources |
| 34 | `recon` | Deep Recon | T1592 | ✓ | — | כן | Comprehensive host, domain, WHOIS, and certificate reconnaissance |
| 35 | `satellite_recon` | Satellite Imagery OSINT | T1591.001 | ✓ | — | לא | Satellite imagery analysis for physical infrastructure mapping: datacenter identification from aeria |
| 36 | `shodan_mass_scan` | Shodan / Censys Mass Scan | T1595.001 | ✓ | — | לא | Internet-wide asset discovery via Shodan, Censys, and FOFA: open port mapping, banner grabbing, defa |
| 37 | `social_media_recon` | Social Media OSINT | T1593.001 | ✓ | — | כן | Cross-platform social media intelligence: LinkedIn org-chart extraction, Twitter/X employee discover |
| 38 | `spear_phishing` | Spear Phishing / BEC | T1566.002 | ✓ | — | כן | AI-crafted spear phishing, BEC wire-fraud simulation, SPF/DKIM spoofing, domain lookalike generation |
| 39 | `telecom_osint` | Telecom Infrastructure OSINT | T1590.002 | ✓ | — | כן | Telecommunications OSINT: BGP ASN ownership mapping, peering relationship analysis, SS7 network topo |
| 40 | `threat_intel_fusion` | Threat Intelligence Fusion Engine | T1597 | ✓ | — | כן | Multi-source threat intelligence fusion: MISP/OpenCTI/TAXII correlation, CVE-to-exploit correlation  |
| 41 | `threat_model_automation` | Automated Threat Modeling Engine | T1595 | ✓ | — | כן | Automated threat model generation from live discovery: STRIDE/PASTA/LINDDUN analysis against discove |
| 42 | `wayback_recon` | Historical Asset Recon | T1593 | ✓ | — | כן | Wayback Machine and CommonCrawl mining: retired endpoint discovery, legacy API key exposure, JavaScr |

### הנדסה חברתית (`social`) — 15 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `brand_impersonation` | Brand Impersonation Engine | T1583.001 | ✓ | — | כן | Brand impersonation attack generation: lookalike domain registration detection, typosquatting varian |
| 2 | `business_email_compromise` | BEC (Business Email Compromise) | T1534 | ✓ | — | כן | Business Email Compromise attacks: CFO/CEO impersonation for wire transfer fraud, vendor invoice man |
| 3 | `callback_phishing` | Callback Phishing Engine | T1566.003 | ✓ | — | לא | Callback phishing (telephone-oriented attack delivery/TOAD): BazarCall/BazaCall methodology simulati |
| 4 | `deepfake_voice_engine` | Deepfake Voice Social Engineering | T1534 | — | **חובה** | לא | Deepfake voice social engineering: real-time voice cloning attack simulation for CEO fraud, family e |
| 5 | `fake_update_engine` | Fake Update Social Engineering | T1189 | ✓ | — | לא | SocGholish-style fake update attacks: browser update lure page generation, JavaScript-based payload  |
| 6 | `insider_threat_engine` | Insider Threat Simulation Engine | T1078.001 | — | **חובה** | לא | Insider threat behavior simulation: privileged access abuse patterns, data exfiltration by legitimat |
| 7 | `linkedin_phishing` | LinkedIn Social Engineering Engine | T1593.001 | ✓ | — | כן | LinkedIn-based social engineering: fake recruiter persona creation, connection request harvesting, I |
| 8 | `physical_social_eng` | Physical Social Engineering Engine | T1534 | — | **חובה** | לא | Physical social engineering simulation: tailgating badge tap playbooks, USB drop attack payload crea |
| 9 | `pretexting_engine` | Pretexting Scenario Engine | T1534 | — | **חובה** | לא | Social engineering pretexting: IT support impersonation playbooks, vendor/auditor pretexting scenari |
| 10 | `qr_phishing` | QR Code Phishing (Quishing) Engine | T1566.001 | ✓ | — | לא | QR code phishing attacks: malicious QR code generation for phishing landing pages, parking ticket/in |
| 11 | `smishing_engine` | SMS Phishing (Smishing) Engine | T1566.003 | ✓ | — | לא | SMS phishing attack framework: delivery receipt fake notifications, bank SMS template generation, pa |
| 12 | `spear_phishing_engine` | Spear Phishing Campaign Engine | T1566.001 | ✓ | — | כן | Targeted spear phishing automation: OSINT-driven personalization, executive lure generation, documen |
| 13 | `typosquatting_phishing` | Typosquatting Phishing Engine | T1583.001 | ✓ | — | כן | Typosquatting attack automation: keyboard proximity domain generation, homoglyph Unicode domain crea |
| 14 | `vishing_engine` | Vishing Attack Engine | T1566.003 | ✓ | — | לא | Voice phishing (vishing) attack simulation: AI voice cloning for executive impersonation, IT helpdes |
| 15 | `watering_hole_attack` | Watering Hole Attack Engine | T1189 | ✓ | — | כן | Watering hole attack simulation: target community website identification, strategic web compromise t |

### Stealth / Evasion (`stealth`) — 51 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `amsi_bypass` | AMSI / EDR Bypass | T1562.001 | ✓ | — | לא | AMSI and EDR bypass techniques: AMSI provider DLL patching, hardware breakpoint-based AMSI bypass, k |
| 2 | `anti_debug_evasion` | Anti-Debug & Anti-Analysis Engine | T1497.001 | — | **חובה** | לא | Anti-debugging and analysis evasion: IsDebuggerPresent API bypass, CheckRemoteDebuggerPresent evasio |
| 3 | `antiforensics` | Anti-Forensics | T1070 | ✓ | — | לא | Log tampering, timestomping, artifact deletion, and evidence destruction sim |
| 4 | `av_bypass_engine` | AV/EDR Bypass Engine | T1562.001 | — | **חובה** | לא | Antivirus and EDR bypass: static signature obfuscation, AMSI bypass techniques, ETW (Event Tracing f |
| 5 | `badusb_hid_attack` | BadUSB / HID Injection Engine | T1091 | ✓ | — | לא | USB-based attack simulation: BadUSB firmware reprogramming emulation, Rubber Ducky keystroke injecti |
| 6 | `behavioral_biometric_attack` | Behavioral Biometric Bypass Engine | T1556 | ✓ | — | כן | Behavioral biometric authentication bypass: typing cadence/rhythm analysis and ML-based forgery, mou |
| 7 | `com_hijacking` | COM Object Hijacking | T1546.015 | ✓ | — | לא | COM object hijacking for persistence and evasion: HKCU registry COM server registration, InprocServe |
| 8 | `continuous_auth_evasion` | Continuous Authentication Evasion Engine | T1078 | ✓ | — | לא | Continuous/behavioral authentication system evasion: behavioral baseline learning and mimicry for UE |
| 9 | `data_exfiltration` | Data Exfiltration | T1048 | ✓ | — | כן | Multi-channel covert exfiltration: DNS-over-HTTPS tunnelling, ICMP covert, SMTP, S3 presigned URL |
| 10 | `deception_evasion` | Anti-Deception Evasion | T1497 | ✓ | — | לא | Sandbox and honeypot evasion: timing-based VM detection, user-interaction checks, hardware fingerpri |
| 11 | `detection_gap_exploiter` | Security Detection Gap Exploitation Engine | T1562 | ✓ | — | לא | Systematic security detection gap analysis and exploitation: SIEM coverage mapping vs MITRE ATT&CK,  |
| 12 | `dll_hijacking` | DLL Hijacking / Side-Loading | T1574.002 | ✓ | — | לא | DLL search order and side-loading exploitation: phantom DLL hijacking, known-DLL override, COM objec |
| 13 | `dll_hijacking_engine` | DLL Hijacking Attack Engine | T1574.001 | — | **חובה** | כן | DLL search order hijacking: missing DLL detection in PATH locations, DLL side-loading via signed app |
| 14 | `dns_tunneling_c2` | DNS Tunneling C2 Channel | T1071.004 | — | **חובה** | כן | DNS-based command and control: DNS TXT/CNAME/A record data encoding, subdomain-based exfiltration, D |
| 15 | `edr_evasion` | Detection Evasion Surface | T1562.001 | ✓ | — | כן | World-class remote detection resilience — WAF/bot UA matrix, rate limits, CSP/cookie gaps, RUM telem |
| 16 | `evil_maid_engine` | Evil Maid Hardware Implant Engine | T1200 | ✓ | — | לא | Evil maid physical access attack simulation: bootloader modification to install keylogger, BIOS/UEFI |
| 17 | `fileless_malware` | Fileless Malware Execution | T1059.001 | ✓ | — | לא | Fileless attack chain: PowerShell in-memory execution, .NET reflective loading, WMI subscription per |
| 18 | `graphene_os_bypass` | Mobile OS Hardening Bypass | T1404 | ✓ | — | לא | Hardened mobile OS bypass: exploit chain against GrapheneOS/CopperheadOS attestation, Android verifi |
| 19 | `https_c2_masquerade` | HTTPS C2 Domain Fronting | T1090.004 | ✓ | — | כן | HTTPS-based C2 masquerading: domain fronting via CDN (Cloudflare/Fastly/Akamai), Google Workspace-fr |
| 20 | `icmp_covert` | ICMP Covert Channel | T1095 | — | **חובה** | כן | ICMP-based covert communication: ICMP tunnel data exfiltration, LOKI-style ICMP shell, ICMPv6 covert |
| 21 | `insider_threat` | Insider Threat Emulation | T1078.002 | ✓ | — | כן | Insider TTP simulation: DLP bypass, excessive-privilege abuse, data staging to cloud storage, shadow |
| 22 | `jit_spray` | JIT Spray Attack Engine | T1203 | ✓ | — | כן | JIT spraying for browser/interpreter exploitation: ActionScript/JavaScript JIT spray, SpiderMonkey/V |
| 23 | `living_off_land` | LOLBins / LOLBAS Abuse | T1218 | ✓ | — | לא | Living-off-the-land binary exploitation: MSBuild/CertUtil payload execution, WMIC lateral movement,  |
| 24 | `log_tampering_engine` | Log Tampering & Destruction | T1070.001 | — | **חובה** | כן | Log tampering techniques: Windows Event Log clearing, syslog UDP injection for log poisoning, Linux  |
| 25 | `log_wiping` | Forensic Log Wiping | T1070 | ✓ | — | לא | Evidence destruction: Windows event log clearing (wevtutil), Linux syslog/auth.log truncation, bash  |
| 26 | `malware_persistence` | Malware Persistence | T1542.003 | ✓ | — | לא | Advanced persistence via UEFI bootkit, kernel rootkit implant, COM hijacking, scheduled task/service |
| 27 | `memory_forensics_evasion` | Memory Forensics Evasion | T1055 | — | **חובה** | לא | Memory forensics evasion: heap spray obfuscation, module stomping, reflective DLL injection, memory- |
| 28 | `microsegmentation_bypass` | Zero Trust Microsegmentation Bypass | T1599 | ✓ | — | כן | Microsegmentation and Zero Trust network bypass: lateral movement via allowed application paths, Ill |
| 29 | `network_traffic_masking` | Network Traffic Masking Engine | T1001 | ✓ | — | כן | Network traffic camouflage: protocol mimicry (legitimate service traffic patterns), traffic timing n |
| 30 | `opsec_intelligence_engine` | Attacker OPSEC & Counter-Intelligence Engine | T1592 | ✓ | — | לא | Operational security (OPSEC) planning for red team operations: attribution prevention techniques, in |
| 31 | `parent_pid_spoof` | Parent PID Spoofing Engine | T1134.004 | ✓ | — | לא | Process parent PID spoofing for detection evasion: STARTUPINFOEX-based PPID manipulation, process cr |
| 32 | `physical_security` | Physical Security Emulation | T1200 | ✓ | — | לא | RFID/NFC badge clone detection, HID proximity card analysis, physical intrusion path mapping |
| 33 | `polymorphic_payload` | Polymorphic / Metamorphic Payload | T1027.002 | ✓ | — | לא | Signature evasion via code transformation: polymorphic XOR/RC4 payload encryption, metamorphic instr |
| 34 | `process_hollowing` | Process Hollowing / Ghosting | T1055.012 | — | **חובה** | לא | Advanced process injection: classic process hollowing, process ghosting (NTFS delete-on-open), proce |
| 35 | `process_injection` | Process Injection | T1055 | ✓ | — | לא | Advanced process injection: DLL hijacking, reflective loading, process hollowing, APC queue injectio |
| 36 | `rootkit_implant` | Kernel / User Rootkit Implant | T1014 | ✓ | — | לא | Rootkit implantation: DKOM process/file hiding, eBPF-based kernel rootkit, UEFI bootkit persistence, |
| 37 | `rootkit_simulation` | Kernel Rootkit Simulation | T1014 | — | **חובה** | לא | Rootkit technique detection and simulation: DKOM (Direct Kernel Object Manipulation), SSDT hook dete |
| 38 | `rop_chain_engine` | ROP Chain Construction Engine | T1203 | ✓ | — | לא | Return-Oriented Programming exploitation: gadget discovery in target binaries, ASLR bypass technique |
| 39 | `sandbox_evasion` | Sandbox Evasion Engine | T1497 | ✓ | — | לא | Malware sandbox evasion techniques: VM detection via CPUID/RDTSC timing, user interaction requiremen |
| 40 | `siem_evasion` | SIEM Log Evasion | T1562.006 | ✓ | — | לא | SIEM/EDR evasion: event log tampering, Sysmon rule bypass, ETW provider disabling, audit-policy mani |
| 41 | `stealth_engine` | Stealth Engine | T1027 | ✓ | — | כן | Covert channel operations: DNS tunneling, ICMP exfil, low-and-slow scanning |
| 42 | `steganography_c2` | Steganography C2 Engine | T1001.002 | ✓ | — | כן | Steganography-based covert communication: LSB image steganography for C2, network protocol covert ch |
| 43 | `syscall_evasion` | Direct Syscall / NTAPI Evasion | T1562.001 | ✓ | — | לא | AV/EDR evasion via direct syscalls: Heaven\ |
| 44 | `thunderbolt_dma_attack` | Thunderbolt / PCIe DMA Attack | T1200 | ✓ | — | לא | Direct Memory Access (DMA) attack via Thunderbolt/USB4/PCIe: Thunderbolt SL1 security level bypass ( |
| 45 | `timestomping` | Timestomping & Metadata Falsification | T1070.006 | ✓ | — | לא | Forensic timeline manipulation: NTFS timestamp modification, MFT entry manipulation, journal/USN log |
| 46 | `timing_evasion_engine` | Timing-Based Evasion Engine | T1497.003 | ✓ | — | כן | Timing-based detection evasion: sleep-based sandbox evasion, operation scheduling during business ho |
| 47 | `timing_sidechannel` | Timing Side-Channel | T1600 | ✓ | — | כן | Microsecond-precision timing attacks against auth, crypto, and rate limiters |
| 48 | `waf_bypass` | WAF Bypass | T1027 | ✓ | — | כן | World-class WAF bypass oracle — vendor fingerprint, encoding/header/path/verb transform matrix, JSON |
| 49 | `waf_ids_bypass` | WAF / IDS Bypass | T1562.001 | ✓ | — | כן | WAF fingerprinting and evasion: unicode normalization, chunked encoding tricks, header injection, HT |
| 50 | `wasm_reverse` | WebAssembly Reverse Engineering | T1027.002 | ✓ | — | כן | WASM binary reverse engineering: obfuscated logic extraction, anti-debug bypass, hidden API key reco |
| 51 | `zero_trust_bypass` | Zero Trust Bypass | T1078 | ✓ | — | כן | Conditional access bypass, device-posture spoofing, MFA fatigue bombing, token exfiltration |

### Supply Chain (`supply_chain`) — 31 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `ai_model_provenance_attack` | AI Model Provenance & Lineage Attack | T1195.001 | ✓ | — | לא | AI model supply chain provenance attack: model card metadata forgery to hide backdoors, training dat |
| 2 | `build_artifact_tamper` | Build Artifact Tampering | T1195.002 | ✓ | — | כן | Build artifact integrity attack: SLSA level 1/2 bypass, artifact checksum mismatch injection, releas |
| 3 | `build_system_compromise` | Build System Compromise Engine | T1195.002 | ✓ | — | כן | Build pipeline compromise: Jenkins/TeamCity/Bamboo exploitation, build server SSRF for lateral movem |
| 4 | `cdn_poisoning_engine` | CDN Cache Poisoning Engine | T1584 | ✓ | — | כן | CDN-level supply chain attacks: CloudFront/Cloudflare/Akamai cache poisoning, CDN origin pull manipu |
| 5 | `ci_cd_poisoning` | Poisoned Pipeline Execution | T1195.002 | ✓ | — | כן | PPE attack variants: direct PPE via forked PR workflow, indirect PPE via poisoned dependencies, 3PP  |
| 6 | `cicd_pipeline` | CI/CD Pipeline Security | T1195.002 | ✓ | — | כן | World-class agentless DevSecOps — 14 CI platforms, GitHub/GitLab/Bitbucket repo plane, GitOps (ArgoC |
| 7 | `code_review_bypass` | Code Review / PR Bypass | T1195.002 | ✓ | — | כן | CODEOWNERS and branch protection bypass: unicode homoglyph in code review, hidden Unicode bidirectio |
| 8 | `compiler_backdoor` | Compiler-Level Backdoor Engine | T1195.003 | ✓ | — | לא | Compiler supply chain attacks: Ken Thompson-style compiler backdoor simulation, LLVM/GCC plugin-base |
| 9 | `container_registry` | Container Registry | T1525 | ✓ | — | כן | DockerHub org exposure, ECR public gallery, /v2/_catalog unauthorized listing |
| 10 | `data_pipeline_attack` | Data Pipeline / ETL Attack | T1565.001 | ✓ | — | כן | Data pipeline tampering: Apache Airflow DAG injection, Kafka consumer MITM, dbt model poisoning, Spa |
| 11 | `dependency_confusion` | Dependency Confusion Attack | T1195.001 | ✓ | — | כן | Dependency confusion exploitation: internal package name enumeration from error messages, public reg |
| 12 | `devsecops_scan` | CI/CD Pipeline Attack | T1195.002 | ✓ | — | כן | CI/CD security: poisoned pipeline execution, secret leakage from env vars, GitHub Actions workflow i |
| 13 | `docker_image_poison` | Docker Image Poisoning Engine | T1195.001 | ✓ | — | לא | Container image supply chain attacks: Docker Hub namespace squatting, base image backdoor insertion, |
| 14 | `github_actions_attack` | GitHub Actions Supply Chain | T1195.002 | ✓ | — | כן | GitHub Actions CI/CD attacks: unpinned action hash exploitation, third-party action compromise, secr |
| 15 | `gitops_attack` | GitOps / IaC Drift Attack | T1195 | ✓ | — | כן | GitOps attack surface: ArgoCD app-of-apps injection, Flux image automation abuse, Helm chart depende |
| 16 | `iac_supply_chain` | IaC Supply Chain Attack | T1195 | ✓ | — | כן | Infrastructure-as-Code supply chain: Terraform module registry poisoning, Helm chart repository MITM |
| 17 | `maven_supply_chain` | Maven/Gradle Supply Chain Attack | T1195.001 | ✓ | — | לא | Java package ecosystem attacks: Maven Central dependency confusion, POM file injection, Gradle build |
| 18 | `npm_package_attack` | NPM Package Hijacking Engine | T1195.001 | ✓ | — | לא | NPM supply chain attacks: dependency confusion attack detection, typosquatting package identificatio |
| 19 | `npm_typosquatting` | npm / PyPI Typosquatting Attack | T1195.001 | ✓ | — | לא | Package registry typosquatting: lookalike package name generation, install-time malicious postinstal |
| 20 | `open_source_backdoor` | Open-Source Project Backdoor | T1195.001 | ✓ | — | לא | OSS supply chain attack: social engineering maintainer account takeover (XZ Utils-style), malicious  |
| 21 | `package_signing_bypass` | Package Signing Bypass | T1553 | ✓ | — | לא | Code signing defeat: GPG key impersonation, Sigstore/Cosign verification bypass, weak SHA1-signed pa |
| 22 | `pypi_supply_chain` | PyPI Supply Chain Attack | T1195.001 | ✓ | — | לא | Python package ecosystem attacks: PyPI dependency confusion, wheel file backdoor detection, setup.py |
| 23 | `sbom_analyzer` | SBOM Analyzer | T1195.001 | ✓ | — | כן | CycloneDX/SPDX/lockfile exposure scan with inline CVE pattern matching |
| 24 | `sbom_forgery_engine` | SBOM Forgery & Analysis Engine | T1195 | ✓ | — | כן | Software Bill of Materials security: SBOM authenticity verification, SPDX/CycloneDX manipulation det |
| 25 | `software_signing_attack` | Software Signing Bypass Engine | T1553.002 | ✓ | — | לא | Code signing security attacks: certificate theft for code signing, Authenticode bypass techniques, k |
| 26 | `supply_chain` | Supply Chain | T1195 | ✓ | — | כן | Third-party dependency and vendor supply chain compromise detection |
| 27 | `third_party_api_attack` | Third-Party API Supply Chain | T1199 | ✓ | — | כן | Third-party API trust exploitation: API aggregator MITM, webhook endpoint hijacking, API key rotatio |
| 28 | `typosquatting_monitor` | Typosquatting Monitor | T1195.001 | ✓ | — | כן | Levenshtein typo generation and NPM/PyPI package impersonation detection |
| 29 | `update_hijacking` | Software Update Hijacking Engine | T1195.002 | ✓ | — | כן | Software update mechanism attacks: TUF (The Update Framework) bypass, unsigned update server comprom |
| 30 | `update_mechanism_hijack` | Software Update Mechanism Hijack | T1195.002 | ✓ | — | כן | Auto-update exploitation: insecure HTTP update URL MITM, TUF (The Update Framework) metadata tamperi |
| 31 | `vendored_code_attack` | Vendored Code / Git Submodule Attack | T1195 | ✓ | — | כן | Vendored dependency attack: git submodule URL redirect, .gitmodules tampering, vendor directory diff |

### Web / API (`web`) — 69 מנועים

| # | מזהה | שם | MITRE | Remote | Agent | יעד | מה עושה (תמצית) |
|---|------|-----|-------|--------|-------|-----|------------------|
| 1 | `api_all_vectors_engine` | Unified API Attack Orchestration Engine | T1190 | ✓ | — | כן | Comprehensive API attack orchestration across all paradigms: REST/GraphQL/gRPC/WebSocket/SOAP/OData/ |
| 2 | `api_fuzzing` | Intelligent API Fuzzing | T1190 | ✓ | — | כן | OpenAPI/Swagger-guided API fuzzing: mass assignment, business-logic bypass, rate-limit evasion, hidd |
| 3 | `api_gateway_attack` | API Gateway / Microservice Attack | T1190 | ✓ | — | כן | API gateway bypass: internal service impersonation, JWT-less microservice direct access, service mes |
| 4 | `api_gateway_bypass` | API Gateway Security Bypass | T1190 | ✓ | — | כן | API gateway security bypass: direct backend access bypassing API gateway, API key brute force, reque |
| 5 | `api_mass_assignment` | API Mass Assignment Scanner | T1548 | ✓ | — | כן | Mass assignment vulnerability detection: hidden field discovery via source diffing, admin flag injec |
| 6 | `api_rate_limit_bypass` | API Rate Limit Bypass | T1499.003 | ✓ | — | כן | Rate limiting evasion techniques: IP rotation via X-Forwarded-For manipulation, header spoofing (X-R |
| 7 | `api_versioning_attack` | Shadow / Deprecated API Attack | T1190 | ✓ | — | כן | Hidden and deprecated API exploitation: version enumeration (v0/v1/beta), undocumented admin endpoin |
| 8 | `ar_vr_attack_engine` | AR / VR Security Attack Engine | T1185 | ✓ | — | כן | Augmented and Virtual Reality security testing: spatial UI redress (3D clickjacking in VR), AR overl |
| 9 | `blockchain_bridge_exploit` | Blockchain Bridge / Cross-Chain Attack | T1496 | ✓ | — | כן | Cross-chain bridge exploitation: lock-mint bridge signature validation bypass (Ronin/Wormhole patter |
| 10 | `bola_idor` | BOLA / IDOR | T1548 | ✓ | — | כן | Broken Object-Level Authorization and Insecure Direct Object Reference attacks |
| 11 | `browser_extension_attack` | Malicious Browser Extension | T1176 | ✓ | — | לא | Browser extension threat: manifest-v3 bypass, cross-origin cookie theft, session token harvest, tab- |
| 12 | `business_logic_flaw` | Business Logic Vulnerability | T1548 | ✓ | — | כן | Business logic exploitation: price manipulation, quantity rollover, coupon abuse, account enumeratio |
| 13 | `cache_poisoning` | Web Cache Poisoning & Deception | T1557 | ✓ | — | כן | v11 SEALED agentless cache-key posture: 51 probe categories, configurable canary domain, sealed cove |
| 14 | `clickjacking` | Clickjacking / UI Redress | T1185 | ✓ | — | כן | Clickjacking via iframe overlay, X-Frame-Options bypass, CSP frame-ancestors evasion, drag-and-drop  |
| 15 | `clickjacking_engine` | Clickjacking / UI Redress Engine | T1185 | ✓ | — | כן | Clickjacking attack surface detection: X-Frame-Options bypass, CSP frame-ancestors abuse, double-fra |
| 16 | `cors_exploit` | CORS Misconfiguration | T1539 | ✓ | — | כן | CORS origin-reflection bypass, null-origin exploit, wildcard credential leakage, pre-flight abuse, c |
| 17 | `cors_misconfiguration` | CORS Misconfiguration Exploit | T1185 | ✓ | — | כן | CORS misconfiguration exploitation: null origin bypass, trusted subdomain pivot, wildcard with crede |
| 18 | `credential_stuffing` | Credential Stuffing | T1110.004 | ✓ | — | כן | Large-scale breach corpus replay, distributed credential stuffing, legacy-protocol MFA bypass (Basic |
| 19 | `csrf_exploit` | CSRF Token Bypass | T1185 | ✓ | — | כן | CSRF attack vectors: token prediction, SameSite bypass, subdomain-based origin confusion, flash-base |
| 20 | `css_injection` | CSS Injection / Data Theft | T1185 | ✓ | — | כן | CSS-based data exfiltration: attribute selector-based secret character extraction, CSS keylogging vi |
| 21 | `deserialization_java` | Java Deserialization Gadget Chain | T1059 | ✓ | — | כן | Java deserialization RCE: ysoserial gadget chain generation, CommonsCollections exploits, Spring/Str |
| 22 | `deserialization_net` | .NET Deserialization Exploiter | T1059 | ✓ | — | כן | .NET deserialization RCE: ViewState exploitation with leaked keys, BinaryFormatter gadget chains, JS |
| 23 | `file_inclusion_rfi` | Remote File Inclusion Engine | T1059 | ✓ | — | כן | Remote and local file inclusion exploitation: PHP wrapper chains (php://filter, php://input, data:// |
| 24 | `file_upload` | File Upload Security | T1190 | ✓ | — | כן | Apex-grade agentless upload arsenal: RTLO/NFKC bypass, cloud-native paths, gzip/Expect-continue, ove |
| 25 | `graphql_attack` | GraphQL & API Security | T1190 | ✓ | — | כן | Agentless GraphQL attack-surface mapping — 41 evidence-only probes: introspection, Clairvoyance reco |
| 26 | `graphql_batching` | GraphQL Batching / DoS | T1499 | ✓ | — | כן | GraphQL attack vectors: query batching for rate-limit bypass, deep recursive query DoS, field sugges |
| 27 | `graphql_deep_attack` | GraphQL Deep Attack Engine | T1190 | ✓ | — | כן | Advanced GraphQL exploitation: introspection abuse for schema harvesting, batching attack for rate l |
| 28 | `graphql_injection` | GraphQL Injection | T1190 | ✓ | — | כן | GraphQL introspection enumeration, query batching abuse, nested query DoS, field-level authorization |
| 29 | `graphql_subscription_attack` | GraphQL Subscription DoS | T1499 | ✓ | — | כן | GraphQL subscription exploitation: subscription flood for resource exhaustion, websocket upgrade abu |
| 30 | `grpc_reflection_attack` | gRPC Reflection Attack | T1190 | ✓ | — | כן | gRPC server reflection exploitation: service enumeration via reflection API, protobuf schema extract |
| 31 | `host_header_injection` | Host Header Injection | T1190 | ✓ | — | כן | HTTP Host header attacks: cache poisoning via X-Forwarded-Host, password reset poisoning, routing-ba |
| 32 | `http_parameter_pollution` | HTTP Parameter Pollution Engine | T1190 | ✓ | — | כן | HTTP Parameter Pollution exploitation: duplicate parameter confusion in WAFs and backends, query str |
| 33 | `http_smuggling` | HTTP Request Smuggling | T1190 | ✓ | — | כן | World-class raw-wire HTTP desync arsenal — CL.TE/TE.CL/0.CL/TE.TE, TE obfuscation oracle, dual-respo |
| 34 | `http2_attack` | HTTP/2 & HTTP/3 Attack Engine | T1190 | ✓ | — | כן | HTTP/2 and HTTP/3 specific attacks: HPACK header compression bombs, RST stream flood, h2c upgrade sm |
| 35 | `idor_advanced` | Advanced IDOR / BOLA Engine | T1078 | ✓ | — | כן | Advanced IDOR exploitation: object reference prediction (sequential ID, UUID, ULID enumeration), ind |
| 36 | `js_prototype_pollution` | Prototype Pollution | T1059.007 | ✓ | — | כן | Server-side and client-side JavaScript prototype pollution: gadget chain to RCE via lodash/jQuery, t |
| 37 | `jwt_advanced_attack` | JWT Advanced Attack Suite | T1550.001 | ✓ | — | כן | Advanced JWT exploitation: alg:none bypass, RS256-to-HS256 confusion, kid header injection (SQLi/pat |
| 38 | `jwt_attack` | JWT Attack | T1550.001 | ✓ | — | כן | alg:none bypass, key confusion, weak-secret brute-force, header injection |
| 39 | `liminal_boundary` | Liminal Boundary | T1190 | ✓ | — | כן | World-first protocol-stack fracture detection — HTTP/1.1↔HTTP/2 auth bypass, method schism, cache Va |
| 40 | `mass_assignment` | Mass Assignment / HPP | T1190 | ✓ | — | כן | Mass assignment and HTTP parameter pollution: JSON body parameter injection, hidden admin fields, pr |
| 41 | `mobile_pentest` | Mobile App Pentest | T1421 | ✓ | — | כן | iOS/Android app security: insecure data storage, deeplink hijacking, certificate pinning bypass, Web |
| 42 | `nosql_deep_injection` | NoSQL Deep Injection Engine | T1190 | ✓ | — | כן | Advanced NoSQL injection: MongoDB where JavaScript injection, GraphQL-to-MongoDB injection, Redis EV |
| 43 | `nosql_injection` | NoSQL Injection Engine | T1190 | ✓ | — | כן | NoSQL injection exploitation: MongoDB operator injection ($where, $regex), CouchDB Mango query bypas |
| 44 | `oauth_oidc` | OAuth / OIDC / SSO Security | T1550.001 | ✓ | — | כן | Supreme-tier agentless OAuth/OIDC/SSO posture: RFC 8414 discovery, JWKS crypto, live redirect_uri/im |
| 45 | `oauth_pkce_attack` | OAuth 2.0 / PKCE Attack | T1550.001 | ✓ | — | כן | OAuth 2.0 advanced attacks: PKCE code_verifier downgrade, authorization code interception, redirect_ |
| 46 | `odata_injection` | OData Query Injection | T1190 | ✓ | — | כן | OData protocol exploitation: filter injection for data enumeration, expand/select for unauthorized d |
| 47 | `open_redirect` | Open Redirect Chain | T1190 | ✓ | — | כן | Open redirect exploitation chain: phishing pre-text, OAuth redirect_uri bypass, SSRF amplification v |
| 48 | `path_traversal` | Path Traversal / LFI / RFI | T1083 | ✓ | — | כן | Directory traversal exploitation: LFI-to-RCE via log poisoning, PHP wrapper chains, ZIP slip, null b |
| 49 | `prototype_pollution` | Prototype Pollution | T1059.007 | ✓ | — | כן | Server-side prototype pollution via JSON merge, query params, body keys |
| 50 | `race_condition_web` | Web Race Condition (TOCTOU) | T1499.003 | ✓ | — | כן | HTTP-level race condition exploitation: single-packet attack, limit overrun, TOCTOU in payment flows |
| 51 | `rce_deserialization` | Deserialization RCE | T1059 | ✓ | — | כן | Java/PHP/.NET deserialization gadget chain exploitation: ysoserial payloads, ViewState tampering, Pi |
| 52 | `smart_contract_audit` | Smart Contract / Blockchain Exploit | T1496 | ✓ | — | כן | Solidity reentrancy, integer overflow, flash loan attacks, front-running MEV exploitation, ERC-20/72 |
| 53 | `soap_injection` | SOAP/XML Injection Engine | T1190 | ✓ | — | כן | SOAP and XML protocol attacks: SOAP action spoofing, XML signature wrapping, DTD-based XXE in SOAP,  |
| 54 | `sqli_advanced` | Advanced SQLi | T1190 | ✓ | — | כן | Time-based blind, error-based, OOB DNS exfil, second-order SQLi, stored procedure abuse |
| 55 | `ssrf_advanced` | SSRF Advanced | T1552.005 | ✓ | — | כן | Agentless SSRF: multi-cloud IMDS credential theft (AWS/GCP/Azure/Alibaba/DO/OCI/ECS multi-role), blo |
| 56 | `ssrf_chain` | SSRF Chain Pivot | T1090.001 | ✓ | — | כן | SSRF chaining: protocol-scheme confusion (gopher/dict/ftp), IMDS v1 metadata theft, internal-service |
| 57 | `ssti` | SSTI | T1190 | ✓ | — | כן | Server-Side Template Injection across Jinja2, Twig, Freemarker, Handlebars |
| 58 | `subdomain_takeover` | Subdomain Takeover Scanner | T1584.001 | ✓ | — | כן | Subdomain takeover exploitation: dangling CNAME detection for 100+ services (AWS S3, GitHub Pages, H |
| 59 | `swagger_abuse` | Swagger/OpenAPI Exploiter | T1190 | ✓ | — | כן | API documentation exploitation: Swagger UI exposed endpoint enumeration, undocumented endpoint disco |
| 60 | `template_injection_adv` | Advanced Template Injection | T1059 | ✓ | — | כן | Advanced SSTI exploitation across all frameworks: Jinja2/Twig/FreeMarker/Velocity/Smarty/Pebble/Groo |
| 61 | `web_cache_deception` | Web Cache Deception | T1185 | ✓ | — | כן | Cache deception attacks: path confusion to cache authenticated responses, CDN cache key manipulation |
| 62 | `web_cache_poison` | Web Cache Poisoning | T1584 | ✓ | — | כן | Cache poisoning via unkeyed headers, fat-GET injection, CDN cache-buster bypass, DOM-based cache dec |
| 63 | `web_cache_poison_adv` | Advanced Web Cache Poisoning | T1185 | ✓ | — | כן | Advanced cache poisoning: unkeyed header injection (X-Forwarded-Scheme, X-Original-URL), cache key c |
| 64 | `web3_dapp_attack` | Web3 / DApp Attack Engine | T1190 | ✓ | — | כן | Web3 and decentralized application attacks: smart contract reentrancy exploitation, flash loan attac |
| 65 | `webrtc_attack` | WebRTC Attack Engine | T1557 | ✓ | — | כן | WebRTC security exploitation: IP address leakage via STUN (VPN bypass), TURN server credential theft |
| 66 | `websocket_attack` | WebSocket Attack | T1071.001 | ✓ | — | כן | Agentless WebSocket DAST at Weissman Standard tier: RFC6455 crypto-verified handshake, differential  |
| 67 | `xss_advanced` | Advanced XSS Engine | T1059.007 | ✓ | — | כן | Comprehensive XSS exploitation: DOM-based, stored, reflected, mutation-based, polyglot payload bypas |
| 68 | `xxe` | XXE | T1190 | ✓ | — | כן | XML External Entity injection via DTD, parameter entities, out-of-band channels |
| 69 | `xxe_injection` | XXE / XML Injection | T1190 | ✓ | — | כן | XML External Entity injection: blind OOB exfiltration, DTD-based SSRF pivot, billion-laugh DoS, SVG/ |

</div>
