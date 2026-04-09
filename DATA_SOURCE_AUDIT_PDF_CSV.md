# Audit: PDF and CSV/Excel Data Source — Live vs Demo

## Summary

**Both the PDF report and the CSV export use real, live data from the bot** — no mock or demo findings are injected. The flow is: **Live feeds (NVD, GitHub, OSV, etc.) → Correlation → DB → PDF/CSV**.

---

## 1. PDF Report — Data Source

### Where the data comes from

| Step | Source | Live? |
|------|--------|------|
| **Scan run** | `correlate_findings_from_db()` in `src/correlation.py` | ✅ Yes |
| **Feeds** | `NVDFeed().fetch()`, `GitHubFeed().fetch()`, `OSVFeed().fetch()`, optional OTX/HIBP | ✅ Real APIs |
| **NVD** | `https://services.nvd.nist.gov/rest/json/cves/2.0` (last 30 days, 200 results) | ✅ Live NVD API |
| **GitHub** | GitHub Security Advisories API | ✅ Live |
| **OSV** | OSV CSV/API | ✅ Live |
| **Fingerprint** | `fingerprint_urls()` / `fingerprint_ip_ranges()` on client domains/IPs | ✅ Live HTTP scan |
| **Validation** | `validate_findings()` (non-destructive PoC checks) | ✅ Live |

### PDF generation flow

1. **Auto-PDF after scan** (`celery_tasks.run_scan_task`, `jobs.auto_check_job`):
   - Findings = output of `correlate_findings_from_db()` + `validate_findings()` (live).
   - These are saved to `ReportRunModel.findings_json` and passed to `generate_report_pdf_auto()` → **PDF content = that live run**.

2. **On-demand PDF** (user clicks "Export PDF" on a report):
   - Loads `run.findings_json` and `run.summary` from DB.
   - That DB data was written from a past scan (same live flow above).
   - `generate_report_pdf()` receives these and builds the PDF → **again, data = what was stored from a real run**.

### What is not live (optional / fallback only)

- **Benchmark section** (industry comparison): if `src.benchmarks.get_benchmark_comparison` is missing, the template uses a fixed fallback (e.g. sector_avg_score 72). This is only for the “vs industry” comparison text, **not** for the list of findings.
- **Global threat intel table**: if `get_global_threat_intel_for_pdf()` fails, the table can be empty. No fake findings are added.

### Code references

- `src/pdf_export.py` (docstring): *"Findings and summary are passed in by the caller; they MUST come from the PostgreSQL/SQLite database ... This module does not generate or inject any fake CVEs or mock data."*
- `src/correlation.py`: `correlate_findings_from_db()` calls `NVDFeed().fetch()`, `GitHubFeed().fetch()`, `OSVFeed().fetch()`, and optionally fingerprint + OTX/HIBP — all real.
- `src/feeds/nvd.py`: Uses `get_with_retry()` to NVD REST API; parses real CVE items into `Finding` objects.

---

## 2. CSV / “Excel” Export — Data Source

### Endpoint

- **GET /api/export/findings** (used by “Export to CSV” in Dashboard, Reports, Command Center).

### Where the data comes from

- Reads **only** from the **`vulnerabilities` table** in the DB.
- Rows in `vulnerabilities` are written by **`_sync_run_findings_to_vulnerabilities()`** in `src/jobs.py`, which is called:
  - When a new report run is created in `run_scan_task` (Celery),
  - When a new report run is created in `auto_check_job`,
  - When the Public API triggers a scan (sync path in `api_public.py`),
  - And when opening an old report that had no vulnerability rows yet (backfill in `report_detail`).

So: **every row in the CSV is a finding that came from a real scan** (same `correlate_findings_from_db` + validation flow), then synced into `vulnerabilities`.

### Code reference

- `src/web/app.py`: `api_export_findings()` runs `db.query(VulnerabilityModel).order_by(...).limit(10000).all()` and exports those rows.
- `VulnerabilityModel` is filled only by `_sync_run_findings_to_vulnerabilities(db, run_id, tenant_id, findings_serializable)` where `findings_serializable` is produced from the live scan.

---

## 3. Conclusion

| Output | Data source | Live from bot? |
|--------|------------|-----------------|
| **PDF report** | Findings/summary from DB (written from scan) or directly from scan task | ✅ Yes — NVD, GitHub, OSV, fingerprint, validation |
| **CSV export** | `vulnerabilities` table, filled from scan runs | ✅ Yes — same scan pipeline |

**Neither PDF nor CSV use demo or mock findings.**  
If there are no findings (e.g. no CVEs matched the client’s tech stack or feeds returned nothing), the PDF will show “No Findings” and the CSV will have no (or fewer) rows — no fake data is added.

---

*Generated: data source audit for Weissman-cybersecurity PDF and CSV/Excel export.*
