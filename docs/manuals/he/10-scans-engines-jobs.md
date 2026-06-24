# 10 — סריקות, מנועים ו-Jobs

## מטרה

תפעול **545 מנועי production**, תור jobs, hubs ב-Command Center, gates של agent-required, ותזמון — למפעילי SOC.

---

## דרישות מקדימות

- תפקיד operator+
- `weissman-worker` רץ (**חובה**)
- client עם scope (ספר 09)
- quota billing (כש-strict פעיל)

---

## קטלוג מנועים

**545+ מנועים** ב-`PRODUCTION_ENGINE_IDS` (`backend/weissman-core/src/models/engine.rs`).

CI: `scripts/verify_engine_wiring.mjs` — build נכשל על פערים.

### סוגי מנוע

| סוג | משמעות | UI |
|-----|--------|-----|
| `real_probe` | סריקה remote | findings חיים |
| `agent_required` | דורש agent | empty עד agent online |
| `alias` | retag | `resolve_engine_id` |
| `special` | e.g. `poe_synthesis` | async job |

API: `GET /api/engines/capabilities`

~45 מנועים דורשים agent. **אין findings מזויפים.**

---

## ארכיטקטורה: scan → finding

```
Operator → Run
  → POST /api/command-center/scan
  → RBAC (operator+)
  → gate_scan_enqueue
  → scope validation
  → INSERT weissman_async_jobs
  → Worker SKIP LOCKED
  → engine_dispatch.rs
  → vulnerabilities
  → UI poll / WebSocket
```

---

## שלב אחר שלב: הרצת סריקה

### 1. בחירת client engine

Hubs לדוגמה:

| נתיב | תחום |
|------|------|
| `/command-center/domain-discovery` | ASM/DNS |
| `/command-center/jwt-lab` | JWT |
| `/command-center/iac-security` | IaC |
| `/command-center/cloud-control-tower` | Cloud |

**Engine Matrix** לחיפוש.

### 2. Target

חייב להיות ב-**authorized domains** או IP ranges.

### 3. הרצה

**Run** או:

```bash
curl -X POST -b cookies.txt https://localhost/api/command-center/scan \
  -H 'Content-Type: application/json' \
  -d '{"engine":"dns_recon","client_id":1,"target":"authorized.example.com"}'
```

### 4. ניטור job

**Jobs** — queued → running → completed/failed.

```bash
journalctl -u weissman-worker -f
```

Concurrency:

- `WEISSMAN_WORKER_LIGHT_CONCURRENCY` (8)
- `WEISSMAN_WORKER_HEAVY_CONCURRENCY` (2)

### 5. תוצאות

Findings ב-hub וב-**Findings** גלובלי.

---

## מנועי agent-required

1. agent online ב-**Agent Management**
2. UI חוסם Run + הוראות התקנה
3. ללא agent — finding informational בלבד

מתקינים: `GET /install/agent.sh`, `GET /install/agent.ps1` (ספר 12).

---

## סריקות מתוזמנות

**Schedules** — cron + engine + client. `gate_scan_enqueue_n` ל-quota.

---

## Bulk pipeline

- **Run All** — quota חודשית
- **PoE Synthesis** — job async
- **Tenant scan** — heavy class

---

## Engine Room / DAG

DAGs מתקדמים; `scan_routing.rs` מקבל engine IDs נוספים.

---

## אימות

```bash
curl -sf -b cookies.txt https://localhost/api/engines/capabilities | jq '.engines | length'
node scripts/verify_engine_wiring.mjs
node scripts/engine_reality_audit.mjs
```

`verify_engine_wiring.mjs` → exit 0, אפס gaps.

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| Jobs תקועים | restart worker |
| שגיאת quota | ספר 08 |
| empty על real_probe | scope; worker logs |
| empty agent engine | תקין עד agent |
| Engine 404 | לא ב-registry |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [09-client-onboarding](09-client-onboarding.md)
- [11-findings-reports](11-findings-reports.md)
- [12-endpoint-agent](12-endpoint-agent.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [01-platform-overview](01-platform-overview.md)
