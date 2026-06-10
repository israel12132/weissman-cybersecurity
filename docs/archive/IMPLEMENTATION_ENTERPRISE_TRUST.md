# Implementation Summary — Enterprise & Trust (All Live Data)

All features below use **real data only**. No mock, fake, or example data.

---

## 1. Trust & Compliance pages

| Page | Route | Data source |
|------|--------|-------------|
| **Compliance** | `/compliance` | `WEISSMAN_REGION`, `RETENTION_DAYS`, `DB_SSL` from env |
| **Methodology** | `/methodology` | Static text describing actual engine (correlation, fuzzer, validation) |
| **Coverage** | `/coverage` | Static list of what we scan / do not scan (actual capabilities) |
| **Status (public)** | `/status` | Redis ping, last run from `ReportRunModel`, harvester file mtime/count |

Nav: **Trust** (Compliance, Methodology, Coverage), **Status** (public).

---

## 2. API & Export

- **Excel export:** `GET /api/export/findings.xlsx` — same query as CSV, from `VulnerabilityModel`. Requires `openpyxl`.
- **Scan-complete webhook:** When a scan round finishes (Celery chord callback), `push_scan_complete_to_webhooks(run_ids, tenant_id, completed_at)` is called. Payload: `event: "scan_complete"`, `run_ids`, `tenant_id`, `completed_at`. All from real run IDs.
- **API rate limit:** Already in place per API key (5 scan triggers per minute).

---

## 3. Security & access

- **IP allowlist:** If `ALLOWED_IPS` (comma-separated) is set, middleware blocks requests whose IP is not in the list. `/status`, `/login`, `/static`, `/docs` are always allowed.
- **Login rate limit:** Existing bruteforce check (5 failures → 10 min block via Redis) unchanged.

---

## 4. Verified & integrity

- **Verified badge:** In Findings table, rows with `source == "fuzzer"` or with `proof` show a "Verified" pill.
- **PDF statement:** Executive Summary includes: *"Data integrity statement: This report is generated exclusively from live database and threat intelligence feeds. No synthetic, mock, or example data is used."*
- **Audit trail:** Findings table shows run ID and link to report; `discovered_at` and `run_id` are from DB.

---

## 5. Dashboard (live only)

- **Last scan:** From `last_run.created_at` (real).
- **Next cycle:** When autopilot schedules the next round, `weissman:next_cycle_at` is set in Redis (Unix timestamp). Dashboard shows "Next cycle in ~X min" from that.
- **Export Excel:** Button links to `/api/export/findings.xlsx`.

---

## 6. Scheduled report email

- **Task:** `weissman.run_scheduled_report_email` (Celery Beat: daily).
- **Data:** Last run from `ReportRunModel` (DB); summary (total, by_severity) from that run.
- **Config:** `REPORT_EMAIL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (optional). If `REPORT_EMAIL` or `SMTP_HOST` is missing, task no-ops.

---

## 7. Environment variables (new/used)

| Variable | Purpose |
|----------|---------|
| `ALLOWED_IPS` | Optional comma-separated IPs; middleware blocks others (except public paths). |
| `RETENTION_DAYS` | Shown on Compliance page (default 365). |
| `REPORT_EMAIL` | Recipient for scheduled report email. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | For scheduled report email. |

---

## 8. No mock data

- Compliance: region, retention, encryption note from env.
- Status: Redis, last run, harvester from live system.
- Dashboard: clients, runs, summary, next_cycle from DB/Redis.
- Excel/CSV: from `VulnerabilityModel` only.
- Webhook scan_complete: run_ids from chord results.
- Scheduled email: last run and summary from DB.
- Verified badge: from `source` and `proof` fields in DB.

All implemented features use only live configuration and database content.
