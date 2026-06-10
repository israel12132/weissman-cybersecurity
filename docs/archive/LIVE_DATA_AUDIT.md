# Live Data Audit — Weissman-cybersecurity

**Date:** 2026-03-12  
**Scope:** Ensure all dashboard and UI data is real, saved to DB, and no simulation/fake/placeholder data is shown. No overwrites or conflicting data sources.

**Client-demo readiness:** All fake fallbacks removed. `/api/findings` and `/api/reports` return `[]` when empty (no VLN-001/Acme placeholder). Dashboard stats use `0` when no score/domains (no hardcoded 82/1842). All 5 SOC engines (supply_chain, osint, asm, bola_idor, ollama_fuzz) run in Rust only; Python is a thin caller. No simulation anywhere for demo.

**100% Rust. No Python.** The bot runs entirely from Rust. One command starts everything from one terminal:

- **`./start_weissman.sh`** — Builds (if needed) and runs the Rust binary. One process: API, dashboard, login, clients CRUD, scan start/stop, background orchestrator. All logs stream to the same terminal (`[Weissman][DB]`, `[Weissman][API]`, `[Weissman][Orchestrator]`). Ctrl+C stops.
- **Dashboard:** `GET /` and `GET /dashboard` serve the same live dashboard: stats (vulns, clients, security score), global scan control (Start/Stop, status from `/api/scan/status`), clients table with per-client **PDF** and **Excel (CSV)** download, recent findings table, and Add Client form. All data from DB; no dummy. War Room opens from the dashboard via "Open War Room" → `/command-center/`.
- **Per-client export (live only):** `GET /api/clients/:id/export/csv` returns CSV of that client's findings (for Excel). `GET /api/clients/:id/report/pdf` returns an HTML report (Print to PDF from browser). Both use only real data from the `vulnerabilities` table.
- **Command Center:** `GET /command-center/` serves the React War Room; WebSocket `/ws/command-center` and `/api/command-center/ticker` feed live data from the DB.
- **DB:** Created automatically on first run (SQLite at `data/app.db`). Tables: clients, users, report_runs, vulnerabilities. If no user exists, a default admin is created (email/password from env `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`, or `admin@weissman.local` / `admin`).
- **No Python, no Celery, no Redis** required to run the bot.

---

## 1. Data flow: dashboard → DB (read)

| Source | Data | Origin |
|--------|------|--------|
| **Dashboard** | clients, last_run, run_history, summary, by_client, by_source, last_scan_by_client, domain_counts, security_score, scan_status, system_status | `get_db()` → `ClientModel`, `ReportRunModel`, `VulnerabilityModel`; Redis for scan toggle; payload_signatures.json mtime for harvester |
| **Findings page** | vulns, clients, client_map, pagination | `_vulns_query(db, tenant_id)` + filters; `_clients_query` for dropdown |
| **Reports list** | runs | `_reports_query(db, tenant_id)` |
| **Report detail** | run, findings, summary, vulns | `ReportRunModel` by id; `VulnerabilityModel` by run_id; findings from `run.findings_json` |
| **Audit log** | logs | `SystemAuditLogModel` |
| **API Keys** | keys | `ApiKeyModel` (tenant-scoped) |
| **Monitored sources** | sources | `MonitoredSourceModel` |
| **System status** | redis_ok, harvester_rules_count, harvester_updated | Redis ping; `payload_signatures.json` read + stat |
| **Tenants / Users** | tenants, users | `TenantModel`, `UserModel` |
| **Alerts** | alerts | `AlertSentModel` |
| **Attack surface** | snapshots | `AttackSurfaceSnapshotModel` |
| **Command Center (React)** | globe, score, ticker | WebSocket init/refresh from `_fetch_globe_sync` / `_fetch_score_sync` (DB: clients, last_run.findings_json); real-time events from Redis PubSub |

**Conclusion:** All displayed data is read from the database or live infrastructure (Redis, file system). No mock or random data in production paths.

---

## 2. Data flow: UI → DB (write)

| Action | Handler | Persistence |
|--------|---------|-------------|
| **Create client** | `POST /clients` | `ClientModel` created; `db.add(client)`; `db.commit()` |
| **Update client** | `POST /clients/{id}` | `client.domains`, `tech_stack`, `ip_ranges`, etc. updated; `db.commit()` |
| **Delete client** | `POST /clients/{id}/delete` | `db.delete(client)`; `db.commit()` |
| **Finding status** | `PUT /api/findings/{id}/status` | `VulnerabilityModel.status` updated; `db.commit()` |
| **Bulk status** | `PUT /api/findings/bulk-status` | `VulnerabilityModel` update by ids; `db.commit()` |
| **Add webhook** | `POST /settings/webhooks/add` | `WebhookModel` created; `db.commit()` |
| **Delete webhook** | `POST /settings/webhooks/{id}/delete` | `db.delete(w)`; `db.commit()` |
| **Create API key** | `POST /settings/api-keys/create` | `ApiKeyModel` created; `db.commit()` |
| **Revoke API key** | `POST /settings/api-keys/{id}/revoke` | `db.delete(k)`; `db.commit()` |
| **Login / MFA** | login, MFA endpoints | Session cookie; `UserModel` (MFA secret) |
| **Scan start** | `POST /api/scan/start` | Redis `weissman:scanning_active`; Celery `run_parallel_scan_dispatcher_task.delay()` |
| **Scan stop** | `POST /api/scan/stop` | Redis flag cleared |

**Conclusion:** All form submissions and actions that change state persist to the database or Redis. No write is demo-only.

---

## 3. Client form: display = DB

- **Edit client:** Domains, IP ranges, and tech stack are stored in DB as JSON arrays. The edit form now receives `domains_display`, `tech_stack_display`, `ip_ranges_display` (newline-separated) so the user sees and edits the real values; on submit, `_form_to_json_array()` converts back to JSON and is saved via `client_update` → `db.commit()`.

---

## 4. PDF and reproduction snippets

- **Before:** When no real proof was available, multilang snippets used a generic `test@example.com` payload.
- **After:** If `proof_curl` is missing or starts with "Manual", all snippets (Bash, Python, JS, Go) show: "Manual verification required. Use Exploit-DB or vendor advisory for PoC." No fake payload is shown.
- **Benchmark section:** PDF now states explicitly that sector averages are "industry reference values (aggregated surveys), not your organization's data."

---

## 5. No overwrites / single source of truth

| Data | Written by | Read by |
|------|------------|---------|
| **ReportRunModel** | `celery_tasks.run_scan_single_client_task` (CVE flow); `jobs` (delta auto_check); `app.py` internal_fuzzer_report_created (fuzzer); `api_public` trigger flow | Dashboard, reports list, report detail, globe/score, findings |
| **VulnerabilityModel** | `jobs._sync_run_findings_to_vulnerabilities` (after run create); `app.py` internal_fuzzer_report_created (standalone row, client_id="fuzzer") | Findings page, report detail status dropdown, CSV export |
| **ClientModel** | `app.py` client_create, client_update; Celery task updates `tech_stack` after fingerprint | Dashboard, clients list, client form, globe, scan dispatch |

- Fuzzer findings create **new** `ReportRunModel` and `VulnerabilityModel` with `client_id="fuzzer"`, `source="fuzzer"`. They never overwrite or merge with NVD/CVE rows.
- Scan flow: one run per cycle per scope; sync writes findings to `VulnerabilityModel` for that run_id. No cross-run overwrite.

---

## 6. Removed or clarified items

| Item | Change |
|------|--------|
| Dashboard error message | Hebrew → English ("Dashboard Error", "Back to login", "Try again") |
| PDF multilang default payload | `test@example.com` → "Manual verification required" when no proof |
| PDF benchmark | Added text: sector averages are industry reference, not client data |
| Client form domains/tech_stack | Display uses DB values as newline-separated; submit saves back to DB via existing POST handlers |

---

## 7. Intentional “reference” data (not client data)

- **benchmarks.SECTOR_AVERAGES:** Used for C-level comparison in PDF and Command Center. Documented as industry reference; PDF text now states this explicitly.
- **Globe intel nodes (lat/lon):** Fixed positions for "Dark Web", "GitHub Intel", "OTX", "NVD" are visual only. Pulses, critical vulns, and threat streams are from DB (clients, last_run.findings_json).

---

## 8. Connectivity summary

| Module | Live data |
|--------|-----------|
| Dashboard | ✅ DB + Redis + harvester file |
| Findings | ✅ VulnerabilityModel (tenant-scoped) |
| Reports | ✅ ReportRunModel |
| Clients | ✅ ClientModel; form display = DB |
| Audit / API Keys / System / Tenants / Users / Alerts / Attack surface | ✅ Corresponding models |
| Command Center (React) | ✅ WebSocket ← _fetch_globe_sync / _fetch_score_sync (DB) + Redis PubSub |
| PDF | ✅ Caller-supplied findings/summary from DB; no fake payloads; benchmark labeled as reference |

All data shown in the dashboard and elsewhere is live and traceable to the server and bot; user inputs are persisted; there are no simulation or fake payloads in production paths, and no conflicting overwrites between fuzzer and CVE flows.
