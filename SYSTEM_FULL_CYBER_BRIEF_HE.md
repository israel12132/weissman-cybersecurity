# Weissman Cybersecurity — תיק מערכת מלא להעברת איש סייבר

**תאריך עדכון:** 2026-06-14  
**מקור:** סינתזה מתוך קוד ותיעוד בריפו (README, docs/architecture.md, docs/operations.md, SECURITY_AND_COMPLIANCE.md, docs/SOC_ENGINES_ARCHITECTURE.md, GETTING_STARTED.md, ONBOARDING_RUNBOOK.md, Cargo workspace).

---

## 1) מטרת המערכת

Weissman היא פלטפורמת סייבר רב-שכבתית עבור Red Team / SOC / MSSP, הכוללת:
- סריקות תקיפה והגנה אוטונומיות על נכסי לקוח מאושרים.
- Command Center תפעולי עם תצוגות Findings, Jobs, KPI, SOAR Playbooks, Ask-Weissman.
- מנגנוני מודיעין איומים (KEV + EPSS), דה-דופליקציה, דיכוי FP, ותעדוף סיכונים.
- Endpoint Agent עם 15 זיהויים מקומיים + UEBA התנהגותי.
- תשתית Multi-Tenant עם RLS בבסיס הנתונים.

---

## 2) טופולוגיה כללית (Production Shape)

1. **Nginx Gateway (:80)**
   - משרת אתר ציבורי + Command Center.
   - מנתב `/api/*` לשרת Rust.
   - כולל הקשחות CSP/HSTS ודחיסה.
2. **weissman-server (Rust/Axum, :8000)**
   - API מרכזי (200+ routes), Auth, RBAC, MFA, Audit, Queueing, Background workers.
3. **PostgreSQL 16 + pgvector**
   - מקור אמת יחיד לנתונים, מיגרציות sqlx + no-tx runner.
   - RLS לכל טבלאות multi-tenant.
4. **weissman-worker (Rust)**
   - צריכת משימות async מ-Postgres queue (`FOR UPDATE SKIP LOCKED`).
5. **Engines (253 production engines + agent capability layer)**
   - Web/Cloud/OT/AI/Supply Chain/Network/Mobile/OSINT/Fuzzing ועוד.
6. **weissman-agent (Endpoint)**
   - Service מקומי (Linux/macOS/Windows), WSS+JWT מול backend.

---

## 3) מבנה ריפו עיקרי

- `backend/weissman-server` — שרת HTTP/WS ראשי.
- `crates/weissman-worker` — worker למשימות async.
- `backend/weissman-core` — מודלים, registry של engines, לוגיקה משותפת.
- `crates/weissman-db` — DB layer + migrations + no-tx migration runner.
- `fingerprint_engine` — לוגיקת engines, persistence, intel, risk, playbooks, HTTP handlers.
- `frontend` — React/Vite Command Center.
- `src/` + `tests/` — שכבת Python legacy/utilities.
- `deploy/` + `docker-compose.yml` — פריסה תפעולית.
- `docs/` + מסמכי root — ארכיטקטורה, תפעול, SLA, תאימות.

---

## 4) רכיבי ליבה — פירוט

### 4.1 API Server (weissman-server)
מספק:
- JWT Auth + TOTP MFA.
- RBAC היררכי: `viewer < analyst < operator < admin < ceo` + `is_superadmin`.
- Endpoints לתפעול לקוחות, סריקות, findings, jobs, audit, playbooks, metrics, ask, onboarding.
- אכיפה: tenant isolation, scope pinning, rate limit, quota, TLS policy.
- OpenAPI 3.1: `/api/openapi.json`, Swagger UI: `/api/docs/`.

### 4.2 Worker (weissman-worker)
- תור מבוסס Postgres (`weissman_async_jobs`).
- Claim עם `SKIP LOCKED` למניעת contention.
- Timeouts לפי סוג עבודה + heartbeats.
- Dispatch ל-engine מתאים והחזרת findings persistence.

### 4.3 Engine Fabric
- רג׳יסטר production ב-`backend/weissman-core/src/models/engine.rs`.
- `PRODUCTION_ENGINE_IDS`: 253 מזהים פעילים מאומתים.
- dispatch רק ל-engine ID מאושר.
- **מדיניות evidence:** אין mock findings; כל finding נשען על probe אמיתי (HTTP/TCP/DNS/TLS/host artifact/intel hit).

### 4.4 Endpoint Agent
- בינרי קטן ורב-פלטפורמי.
- 15 זיהויי host (process/log/usb/arp/persistence/edr וכו').
- UEBA baseline sampling לפי `hour_of_week`, פורטים/תהליכים/משתמשים/משאבים/failed logins.
- אנומליות מבוססות z-score נרשמות בשרת.

### 4.5 Frontend Command Center
- React + Vite + Tailwind.
- אזורים מרכזיים: Cockpit, Findings, Engines Matrix, Engine Detail, Jobs, Playbooks, AskWeissman, Audit Log.
- Dev proxy: `/api` -> `http://127.0.0.1:8000`.

---

## 5) אבטחה ובקרות (Server-Enforced)

1. **RLS רב-דיירי (tenant isolation)** ברמת DB עם `tenant_id` + policies.
2. **Audit logging** לכל פעולה מאומתת (כולל IP, משתמש, action).
3. **Scope validation**: מניעת סריקה מחוץ לדומיינים/IP מאושרים.
4. **Rate limit פר-tenant** + **AI daily quota**.
5. **MFA enforcement** ברמת tenant policy.
6. **TLS policy**: מצב insecure נדחה בפרודקשן.
7. **API keys hashed בלבד** (ללא plaintext at rest).
8. **NL→SQL guardrails**:
   - ה-LLM מחזיר QueryPlan JSON בלבד (לא SQL גולמי).
   - קומפילציה מול allow-list של טבלאות/עמודות/אופרטורים.
   - אכיפת tenant filter ו-limit cap.
   - הרצה דרך role ייעודי `weissman_ro` (SELECT-only, timeouts קשיחים).
9. **Constant-time comparisons** לבדיקות token/signature רגישות.
10. **Webhook signing/verification** ב-HMAC SHA-256.
11. **False-positive suppression loop**: אחרי 3 FP לאותה חתימה, סימון אוטומטי עם traceability.

---

## 6) מודיעין איומים וניקוד

- **KEV (CISA)**: refresh כל 6 שעות, נשמר ב-`kev_intel`.
- **EPSS (FIRST)**: refresh/backfill כל 12 שעות + enrichment בזמן persist finding.
- finding CVE-tagged מועשר בשדות EPSS/KEV.
- אם feed לא זמין: לא מזייפים נתון; נשמר finding עם enrichment חסר ו-retry מאוחר.

---

## 7) זרימות נתונים קריטיות

### 7.1 Scan → Finding
1. בקשת scan ל-API.
2. אימות engine/scope/rbac/quota.
3. INSERT job ל-queue.
4. worker תובע job ומריץ engine.
5. persist:
   - finding_id יציב (hash deterministic),
   - enrichment KEV/EPSS,
   - suppression checks,
   - upsert `vulnerabilities`,
   - clustering,
   - trigger ל-SOAR dispatch.
6. חשיפה ב-`/api/findings`, `/api/dashboard/exec-kpis` ועוד.

### 7.2 Ask Weissman (NL→SQL)
1. UI שולח שאלה.
2. LLM מחזיר plan מוגבל.
3. backend מאמת ומקמפל SQL פרמטרי מוגן.
4. שאילתה רצה על `weissman_ro` בלבד.
5. תוצאות + SQL קומפילטיבי חוזרות ל-UI.
6. audit מלא נשמר ב-`nl_query_audit`.

### 7.3 Agent UEBA
1. Agent מעלה sample ל-`/api/ueba/ingest`.
2. server מחשב baseline חלוני (7 ימים, bucket שעה-בשבוע).
3. סף `|z| > 3` = medium, `|z| > 6` = high.
4. אנומליות זמינות ב-`/api/ueba/anomalies`.

---

## 8) בסיס נתונים — נקודות מפתח

### 8.1 Roles
- `weissman_app` — role אפליקטיבי (RLS enforced).
- `weissman_auth` — login plane ייעודי.
- `weissman_ro` — SELECT-only ל-Ask API.

### 8.2 דומייני טבלאות (מדגם מרכזי)
- Auth/Tenant: `tenants`, `users`, `user_refresh_tokens`, `audit_logs`
- Clients/Scope: `clients`, `client_asset_value_rules`
- Findings: `vulnerabilities`, `weissman_finding_clusters`
- Intel: `kev_intel`, `epss_intel`, `finding_suppressions`
- Queue/Jobs: `weissman_async_jobs`
- Agent/UEBA: `endpoint_agents`, `endpoint_agent_tasks`, `agent_metric_samples`, `agent_anomalies`
- SOAR: `weissman_playbooks`, `weissman_playbook_runs`
- NL Query: `nl_query_audit`
- Graph/Risk: `risk_graph_nodes`, `risk_graph_edges`, `attack_path_snapshots`

### 8.3 Migrations
- source of truth: `crates/weissman-db/migrations/`.
- transactional migrations: `sqlx::migrate!`.
- no-transaction migrations via header `-- weissman:no-transaction`.
- checksum SHA-384 ב-`_sqlx_migrations`; mismatch חוסם עלייה.

---

## 9) SOAR / Playbooks

Trigger DSL על finding event עם תנאים כגון severity/kev/epss/exposure/engine/cooldown.

Actions נתמכות:
- `set_status`
- `slack_notify`
- `webhook`
- `http_post`
- `open_pr`
- `isolate_host`
- `page_oncall`

Dispatch מתבצע best-effort לאחר commit DB כדי לא לעכב transaction קריטי של persist.

---

## 10) Red Team / Engine Domains

קבוצות עיקריות:
- Web app attacks (XSS/SQLi/SSRF/IDOR/BOLA/GraphQL וכו')
- Cloud attacks (AWS/Azure/K8s/Serverless)
- OT/ICS protocol assessments (Modbus, DNP3, S7, IEC 61850)
- AI/LLM attacks (prompt injection, jailbreak, RAG poisoning)
- Supply-chain & CI/CD attacks
- OSINT/ASM discovery
- Network stealth/evasion/covert channels
- Crypto/TLS/PKI posture
- Fuzzing (semantic/generative/llm-assisted)
- Mobile attack surface
- Endpoint agent-required detections

---

## 11) תצורה תפעולית (Env)

### Required
- `DATABASE_URL`
- `WEISSMAN_JWT_SECRET`
- `WEISSMAN_MIGRATE_URL`

### Recommended/Operational
- `WEISSMAN_AUTH_DATABASE_URL`
- `WEISSMAN_READ_ONLY_DATABASE_URL`
- `WEISSMAN_REGION`
- `WEISSMAN_PUBLIC_URL`
- `WEISSMAN_LOG_FORMAT`

### Feature toggles
- `WEISSMAN_SELF_SERVE_SIGNUP`
- `WEISSMAN_BILLING_STRICT`
- `WEISSMAN_INTEL_KEV_ENABLED`
- `WEISSMAN_INTEL_EPSS_ENABLED`
- `WEISSMAN_SOVEREIGN_SELF_SCAN_INTERVAL_SECS`

### LLM/Embeddings
- `OPENAI_BASE_URL` / `WEISSMAN_LLM_BASE_URL`
- `OPENAI_API_KEY` / `WEISSMAN_LLM_API_KEY`
- `WEISSMAN_EMBEDDINGS_MODEL`
- `WEISSMAN_NL_QUERY_MODEL`

---

## 12) פריסה ותפעול

### Docker-first
- `docker compose up -d` מפעיל postgres + backend + worker + gateway.
- backend מריץ migrations בעלייה.

### Native Dev
- build workspace ב-Cargo.
- הרצת `weissman-server` ו-`weissman-worker` בנפרד.
- frontend dev על 5173.

### ניטור
- `/api/metrics` ל-Prometheus.
- `/status` עמוד סטטוס ציבורי.
- לוגים JSON עם `WEISSMAN_LOG_FORMAT=json`.

---

## 13) SLA וסטטוס שירות

- Availability target: **99.9%** חודשי.
- הגדרת unavailable: פגיעה ביכולות ליבה (API/Job orchestration/Dashboard).
- Credits: 10% או 25% לפי רף זמינות.
- תגובת incident קריטי: יעד עד 4 שעות עסקים.

---

## 14) בדיקות, איכות ו-CI

תיעוד הריפו מגדיר:
- Rust: `cargo fmt --check`, `cargo clippy --workspace`, `cargo test --workspace`
- Python: `ruff check src/ tests/`, `python3 -m pytest tests/unit/ -q`
- Frontend: `cd frontend && npm run build`

בבדיקה בסביבת עבודה זו לפני כתיבת המסמך:
- חסר `crates/weissman-agent/Cargo.toml` ולכן בדיקות workspace של Rust נכשלו ב-bootstrap.
- חסרים כלים/תלויות (`ruff`, `pytest`, `vite`) ולכן הרצות Python/Frontend לא הושלמו.

כלומר: מצב הסביבה המקומית הנוכחית אינו משקף בהכרח מצב CI מלא, אלא חסרי bootstrap מקומיים.

---

## 15) מגבלות מידע ושמירת סודיות

המסמך הזה מקיף את כלל רכיבי המערכת ברמת ארכיטקטורה, תפעול, זרימות, אבטחה ודאטה כפי שנמצאו בריפו.  
**לא נכללו סודות חיים** (מפתחות, טוקנים, סיסמאות אמיתיות) מטעמי אבטחת מידע, גם לצורך handoff מקצועי.

---

## 16) קבצי מקור מומלצים להמשך בדיקת איש הסייבר

1. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/README.md`
2. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/docs/architecture.md`
3. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/docs/operations.md`
4. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/docs/SOC_ENGINES_ARCHITECTURE.md`
5. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/SECURITY_AND_COMPLIANCE.md`
6. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/SLA_AND_STATUS.md`
7. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/GETTING_STARTED.md`
8. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/ONBOARDING_RUNBOOK.md`
9. `/home/runner/work/weissman-cybersecurity/weissman-cybersecurity/israel12132/weissman-cybersecurity/Cargo.toml`

