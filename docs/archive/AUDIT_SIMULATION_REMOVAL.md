# MANDATORY SYSTEM AUDIT: Simulation, Mock & Fake Data Removal

**Date:** 2026-03-12  
**Scope:** Full repository (backend + frontend)  
**Mission:** 100% data-driven system; zero demo/mock/simulated/fake logic in production paths.

---

## 1. FILES CLEANED (Search & Destroy)

### Backend (Python)

| File | Change |
|------|--------|
| **src/pdf_export.py** | Added module docstring: data MUST come from DB (caller); no fake CVEs. When `total == 0` or no findings, Executive Summary now explicitly states "No Findings." and clarifies that all data is from the live database with no mock or simulated findings. |
| **src/pdf_export.py** | `rows_html` already had fallback: `'<tr><td colspan="8">No findings in this run.</td></tr>'` when `findings` is empty — confirmed; no fake rows. |
| **src/proxy_rotation.py** | `random.choice(proxies)` — **kept**. Legitimate: selects one proxy from the list for rotation (stealth), not simulation. |
| **src/threat_intel.py** | `time.sleep(60)` and `time.sleep(RATE_DELAY_SEC)` — **kept**. Used for GitHub API rate limiting (avoid 429), not for simulating work. |
| **src/http_client.py** | `wait_random` (jitter) in tenacity — **kept**. Retry backoff jitter for real API resilience. |
| **src/benchmarks.py** | `SECTOR_AVERAGES` — **kept**. Reference industry averages for C-level comparison (documented); not mock client findings. |
| **src/darkweb_intel.py** | No fake leak generation found. All results from real Tor/scraper requests and `MONITORED_SOURCES` DB. Comment "no hardcoded limit" refers to unbounded result lists. |
| **src/github_monitor.py** | No mock. Real GitHub Events API and profile events; IP rotation via http_client. |
| **src/jobs.py** | No simulation delay. Orchestrator uses real DB, correlation, validation, Celery. |
| **src/correlation.py** | Feeds (NVD, GitHub, OSV, OTX, HIBP) are real API calls; no hardcoded fake CVE lists. |
| **src/feeds/nvd.py** | Fetches from NVD API only; no fallback fake CVE list. |

### Frontend (React)

| File | Change |
|------|--------|
| **frontend/src/components/BackgroundCycler.jsx** | **Removed all `Math.random()`.** Matrix Rain: character and drop reset now use deterministic formulas `(i + floor(drops[i]/10)) % 96` and `(i + drops[i]) % 41 === 0`. Neon Dust: positions and animation use index-based values `(i*17)%100`, `(i*23+31)%100`, `(i%5)*0.8`, `3+(i%4)` — no random placement or timing. |
| **frontend/src/components/Globe.jsx** | Already clean. Arcs and pulses only from WebSocket `realtimeArcs` / `realtimePulses`; no `Math.random` or fake arcs. Comment present: "Real-time arcs: only from WebSocket events (no simulation)". |
| **frontend/src/App.jsx** | `setInterval` for live clock (`setNow`) and `setTimeout` for arc/pulse/highlight cleanup — **kept**. Real UX timers, not data simulation. |
| **frontend/src/components/CinematicBackground.jsx** | No `Math.random`. Uses `Math.sin(t + i*0.1)` for deterministic grid animation. |
| **frontend/src/components/EmergencyAlert.jsx** | `setTimeout` for banner hide — **kept**. Real animation lifecycle. |

### Not Changed (Intentional)

- **src/auth_enterprise.py** — `pyotp.random_base32()`: used for TOTP secret generation; legitimate.
- **src/web/app.py** — `asyncio.sleep(60)` in WebSocket refresh loop: real 60s refresh interval, not fake delay.
- **integrity_placeholder** in pdf_export: temporary string replaced by real SHA-256 hash; not mock data.
- **recon_engine.py** — word `"demo"` in subdomain filter list: filter keyword (e.g. skip demo.example.com), not mock data.

---

## 2. LIVE CONNECTION ENFORCEMENT

### PDF Reports

- **Source of truth:** `findings` and `summary` are passed by the caller (Celery task or FastAPI route). Callers build these from **PostgreSQL/SQLite** (`ReportRunModel`, correlation, validation). This module does not fetch DB directly but **never injects fake CVEs or mock findings**.
- **Empty state:** If the database has no findings for the run, `findings` is `[]` and `total` is 0. The report shows:
  - Findings table: one row with "No findings in this run."
  - Executive Summary: "Total findings: 0. No Findings."
- **Benchmark fallback:** If `get_benchmark_comparison` fails (e.g. import error), a fixed fallback object is used for PDF layout only; it is not presented as real client data.

### CVE Engine

- **NVD:** `src/feeds/nvd.py` calls NVD API `https://services.nvd.nist.gov/rest/json/cves/2.0` with date range; no local fake CVE list.
- **Other feeds:** GitHub, OSV, OTX, HIBP are real API/clients; correlation uses their results only.

### Intel Modules

- **Dark Web (`darkweb_intel.py`):** Requests go through Tor proxy; results from Ahmia, Onion.live, optional Haystack/DeepSearch and Pastebin; new sources validated and stored in `monitored_sources` table. No fake leak list.
- **GitHub (`github_monitor.py`):** Uses GitHub Events API and user events; exploit-like repos filtered by signature; no hardcoded fake repos.

### Globe / War Room

- **Data flow:** Globe and Live Intel Terminal consume only:
  - Initial/refresh payload from WebSocket (`type: init` / `type: refresh`) — data from `_fetch_globe_sync` / `_fetch_score_sync` (DB).
  - Real-time events from Redis PubSub (scan pulses, darkweb hits, critical CVEs, emergency alerts).
- **No fake arcs or pulses:** All arcs and red pulses are created from WebSocket events with real `targetLabel` / coordinates. When the server is offline, the globe shows "CONNECTION LOST" and clears arcs/pulses.

---

## 3. CONNECTIVITY STATUS SUMMARY

| Module | Status | Notes |
|--------|--------|------|
| **Recon** | 100% data-driven | Subdomains/buckets from CT, DNS, cloud APIs; results stored in DB/snapshots. |
| **Dark Web** | 100% data-driven | Tor requests + scraped/validated sources; alerts from real hits; new sources in DB. |
| **GitHub** | 100% data-driven | Events API + profile watch; real repos and pushes; no mock events. |
| **PDF** | 100% data-driven | Content from caller-supplied findings/summary (DB); "No Findings" when empty. |
| **DB** | Single source of truth | Report runs, clients, findings, alerts, monitored sources — no fake rows injected. |
| **Globe / Command Center** | 100% data-driven | WebSocket init/refresh from DB; events from Redis PubSub; no fake arcs or pulses. |
| **CVE / Feeds** | 100% live | NVD, GitHub, OSV, OTX, HIBP — real APIs only. |

---

## 4. SUMMARY FOR STAKEHOLDERS

- **pdf_export.py:** No fake CVE or finding lists; report states "No Findings" when there are none; docstring states data must come from DB.
- **darkweb_intel.py:** No fabricated leaks; all results from Scraper/Tor and DB.
- **Globe.jsx:** No `Math.random` or fake arcs; arcs/pulses only from WebSocket.
- **BackgroundCycler.jsx:** All `Math.random` removed; Matrix Rain and Neon Dust use deterministic formulas.
- **Orchestrator / jobs:** No artificial delay to simulate work; all sleeps are rate limiting or refresh intervals.

The system is **100% truth**: no simulations, mocks, or fake data in production data paths. Reference data (sector benchmarks, fallback PDF copy) is documented and not presented as live client findings.
