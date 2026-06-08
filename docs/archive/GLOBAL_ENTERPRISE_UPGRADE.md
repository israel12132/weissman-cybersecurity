# Weissman-cybersecurity: Global Enterprise Supremacy Upgrade

This document summarizes the **Global Reconnaissance**, **Agentic Red-Teaming**, **Supply Chain**, **Predictive Analytics**, and **Multi-Tenancy** capabilities added for world-scale deployments.

---

## Phase 1: Global Reconnaissance Engine

### Subdomain Enumeration (Passive + Active)
- **Certificate Transparency (CT)**: `recon_engine.enumerate_subdomains_ct(domain)` — crt.sh.
- **WHOIS / passive DNS**: `enumerate_subdomains_whois(domain)` — HackerTarget hostsearch.
- **DNS brute-force**: Rust `fingerprint_engine subdomains <domain>` (high concurrency); Python fallback with socket.

### Multi-Cloud Asset Discovery
- **AWS S3**: `scan_cloud_buckets()` — existence + listability.
- **Azure Blob**: same; containers like `uploads`, `backup`, `data`.
- **GCP Storage**: `scan_gcp_buckets()` — `storage.googleapis.com/{bucket}` and `{bucket}.storage.googleapis.com`.
- **Exposed APIs**: `check_exposed_api_endpoints(base_urls)` — `/api`, `/graphql`, `/swagger.json`, `/.env`, `/staging`, `/dev`.

### IP-to-Org Mapping (BGP/ASN)
- **`src/ip_org.py`**:
  - `get_ip_org(ip)` — RIPE Stat + ipinfo.io fallback → `asn`, `org`, `netname`, `country`.
  - `ip_belongs_to_org(ip, org_keywords)` — heuristic match for scope validation.

### Discovery Job
- `_discovery_job()` runs every **12 hours** with CT, WHOIS, DNS brute, S3, Azure, GCP (no exposed API by default to reduce noise).

---

## Phase 2: Agentic AI Red-Teaming

### Autonomous “Next Steps”
- **`src/agent_redteam.py`**:
  - `get_next_steps(port, service, tech_stack, finding_summary)` → list of `{ action, rationale, priority }`.
  - Rule-based mapping per service (Jenkins, Docker, Redis, Elasticsearch, nginx, Jira, etc.): e.g. “Check /scriptApproval”, “Test default credentials”, “Enumerate config for secrets”.

### Contextual Fuzzing (AI-Guided Payloads)
- **`get_fuzzer_payloads_for_tech(tech_stack)`** — returns payloads per tech (Jenkins, nginx, PHP, Node, GraphQL, SQL, etc.).
- **`write_fuzzer_payloads_file(tech_stack)`** — writes temp file; Rust fuzzer reads **`FUZZ_PAYLOADS_FILE`** and runs these payloads in addition to built-in mutations.
- **Python**: `run_fuzzer_binary(..., tech_stack=...)` sets `FUZZ_PAYLOADS_FILE` when tech_stack is provided.
- **Rust**: `fuzzer.rs` loads guided payloads and merges with `Mutator::mutations()`.

---

## Phase 3: Supply Chain & Repository Monitoring

### Supply Chain Intelligence
- **`src/supply_chain.py`**:
  - **NPM**: `search_npm_packages(org_or_prefix)` — registry.npmjs.org.
  - **PyPI**: `search_pypi_packages(org_or_prefix)` — package lookup.
  - **Typosquatting**: `_typosquat_similar(a, b)` — similar names flagged.
  - **OSV**: `check_osv_for_package(ecosystem, name)` — vulnerability count.
  - **`run_supply_chain_scan(org_name, domain, check_typosquat, check_compromised)`** — combined scan.

### Secret Leak Scan (GitHub)
- **`src/secret_scan.py`**:
  - **`search_github_code(org_or_query, token, max_results)`** — GitHub Code Search for org + “api_key”, “.env”, “password”.
  - **`run_secret_scan(org_name, token)`** — uses `GITHUB_TOKEN` from env; returns list of `PotentialLeak(repo, path, url, snippet, pattern, severity)`.

### Scheduler
- **`_supply_chain_secret_job()`** runs every **24 hours** per client (org name + domain from scope).

---

## Phase 4: Predictive Analytics & Remediation

### Weissman Priority Score
- **`src/cvss_epss.py`**:
  - **`weissman_priority_score(cvss_value, severity, epss_value, asset_criticality)`**  
    Formula: **CVSS × EPSS × Asset_Criticality**, scaled to 0–100.  
    Used to prioritize findings (exploit likelihood + impact).
  - **`cvss_severity_to_numeric(severity)`** — Critical 10, High 8.5, Medium 5, Low 2.

### One-Click Remediation
- **`src/remediation.py`**:
  - **`get_remediation_snippet(finding_type, tech_stack, severity, cve_id, component)`**  
    Returns exact patch/config/code (Nginx, Apache, PHP, Node, Java, Docker) per finding type (LFI, SQLi, XSS, deserialization, default).
- **PDF**: Each finding row includes this snippet (tech-aware); executive summary includes **Weissman Priority Score** and “one-click remediation” wording.

---

## Phase 5: Architecture Scalability

### Multi-Tenancy
- **`TenantModel`**: `id`, `name`, `slug`, `settings_json`, timestamps.
- **`ClientModel.tenant_id`**: optional FK to `tenants`; null = default tenant. Supports thousands of corporate accounts with tenant isolation.
- **SQLite**: `init_db()` runs `ALTER TABLE clients ADD COLUMN tenant_id` (try/except).
- **PostgreSQL**: Alembic **`003_multi_tenancy.py`** creates `tenants` and `client.tenant_id`.

### Global Workers (Rust)
- **`WEISSMAN_REGION`**: optional env (e.g. `US-East`, `EU-West`, `Asia-Pacific`) for logging; workers can be deployed per region.
- **Proxy**: For geo-bypass, run workers behind a forward proxy or in the target region; system `HTTP_PROXY` can be used where the runtime respects it.

---

## New / Updated Files

| Path | Description |
|------|-------------|
| `src/ip_org.py` | IP-to-org (RIPE, ipinfo), `ip_belongs_to_org`. |
| `src/agent_redteam.py` | Next steps, contextual fuzzer payloads, `write_fuzzer_payloads_file`. |
| `src/supply_chain.py` | NPM/PyPI, typosquat, OSV; `run_supply_chain_scan`. |
| `src/secret_scan.py` | GitHub code search for leaks; `run_secret_scan`. |
| `src/remediation.py` | One-click remediation snippets per tech/finding type. |
| `src/cvss_epss.py` | `weissman_priority_score`, `cvss_severity_to_numeric`. |
| `src/recon_engine.py` | WHOIS, GCP buckets, exposed API check; `run_full_recon(..., use_whois, use_gcp, use_exposed_api)`. |
| `src/pdf_export.py` | Priority score, `get_remediation_snippet` in findings, executive text. |
| `src/database.py` | `TenantModel`, `ClientModel.tenant_id`. |
| `src/fingerprint.py` | `run_fuzzer_binary(..., tech_stack=...)`. |
| `fingerprint_engine/src/fuzzer.rs` | `FUZZ_PAYLOADS_FILE`, `load_guided_payloads()`. |
| `fingerprint_engine/src/fingerprint.rs` | `WEISSMAN_REGION` comment. |
| `alembic/versions/003_multi_tenancy.py` | Tenants table, `client.tenant_id`. |

---

## Security & Integrity

- No placeholders: all modules use real APIs (crt.sh, HackerTarget, RIPE, ipinfo, NPM, PyPI, OSV, GitHub) and deterministic logic.
- Remediation templates are code/config snippets, not executable untrusted code.
- GitHub secret scan respects rate limits and uses `GITHUB_TOKEN` from env when set.
- Multi-tenancy allows per-tenant isolation and future quotas/limits in `settings_json`.

This upgrade aligns the platform with global-scale, enterprise deployments (e.g. Google, Amazon, banks) with recon, red-team logic, supply chain, priority scoring, remediation, and multi-tenant architecture.
