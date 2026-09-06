# 01 — סקירת פלטפורמה וארכיטקטורה

## מה זה Weissman

Weissman Cybersecurity היא **פלטפורמת offensive-security והגנה אקטיבית** ל-MSSP, צוותי SOC וארגונים. היא כוללת:

- **שרת API ב-Rust** (`weissman-server`) — HTTP + WebSocket על פורט 8000
- **Worker אסינכרוני** (`weissman-worker`) — pipelines של סריקות
- **Command Center ב-React** — SPA ב-`/command-center/`
- **Agent לנקודת קצה** (`weissman-agent`) — detections + UEBA
- **573 מנועי production** — כל אחד מחובר ל-probe אמיתי

**עקרון מרכזי:** Findings מגיעים **רק מ-probes חיים**. מנועים שדורשים Agent מציגים empty state כנה עד ש-Agent מחובר — **ללא תוצאות מזויפות**.

---

## דיאגרמת ארכיטקטורה

```
דפדפן → Nginx Gateway (:80 → :8080)
         ├─ /command-center/*  → React static
         ├─ /api/*             → weissman-server :8000
         └─ /ws/*              → WebSocket

weissman-server
  ├─ Auth (JWT, cookies, MFA, OIDC/SAML)
  ├─ RBAC (viewer → analyst → operator → admin → ceo)
  ├─ Billing (Paddle + quota חודשי)
  └─ Enqueue → weissman_async_jobs

weissman-worker
  └─ מריץ מנועים → שומר findings

PostgreSQL 16 + pgvector
  ├─ RLS לנתוני tenant
  └─ Migrations מ-crates/weissman-db/

Redis 7
  └─ Rate limits, lockout, telemetry (חובה ב-multi-replica)
```

---

## סוגי מנועים

| סוג | משמעות | התנהגות UI |
|-----|--------|------------|
| `real_probe` | סריקה remote ללא agent | סריקה רגילה |
| `agent_required` | דורש agent | Empty state עד agent online |
| `alias` | מנוע קנוני אחר | `resolve_engine_id` |
| `special` | למשל `poe_synthesis` | דרך async job |

API: `GET /api/engines/capabilities`

---

## מודולים עיקריים

| מודול | נתיב UI | Backend |
|--------|---------|---------|
| לקוחות ו-scope | `/clients` | `clients` |
| מרכזי מנועים | `/jwt-lab`, `/iac-security`… | `POST /api/command-center/scan` |
| Jobs | `/jobs` | `weissman_async_jobs` |
| Findings | `/findings` | `vulnerabilities` + KEV/EPSS |
| Agent | Agent Management | `/api/agents/*` |
| Billing | Billing | Paddle |
| SOAR | Playbooks | `soar_playbook.rs` |
| Council / AI | Council queue | jobs + LLM |

---

## זרימת סריקה אחת

1. מפעיל לוחץ **Run**
2. `POST /api/command-center/scan`
3. השרת בודק RBAC, **quota**, scope
4. Job נכנס לתור → worker מריץ
5. `engine_dispatch` מבצע probe
6. Findings נשמרים ב-`vulnerabilities`
7. UI מציג תוצאות

---

## מבנה מאגר

| נתיב | תפקיד |
|------|--------|
| `backend/weissman-server/` | שרת HTTP |
| `crates/weissman-worker/` | Worker |
| `crates/weissman-agent/` | Agent |
| `fingerprint_engine/` | מנועים, handlers |
| `frontend/` | Command Center |
| `deploy/` | Docker, nginx, k8s |
| `docs/manuals/` | חבילת ספרים זו |

---

## ספרים קשורים

- [02-installation-docker](02-installation-docker.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
