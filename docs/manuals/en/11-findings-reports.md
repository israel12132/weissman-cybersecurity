# 11 — Findings & Reports

## Purpose

Triage security findings, manage status workflows, enrich with threat intel (KEV/EPSS), export customer deliverables (PDF/CSV), and use cryptographic proof artifacts where applicable.

---

## Prerequisites

- Analyst role or higher for triage actions
- At least one completed scan (manual 10)
- Optional: intel feeds enabled (`WEISSMAN_INTEL_KEV_ENABLED`, `WEISSMAN_INTEL_EPSS_ENABLED`)

---

## Findings data model

Findings persist in PostgreSQL `vulnerabilities` table (tenant-scoped via RLS).

Each finding includes:

| Field | Description |
|-------|-------------|
| `signature` | Dedup key — same issue upserts, not duplicates |
| `severity` | Critical / High / Medium / Low / Info |
| `engine_id` | Source engine |
| `client_id` | Associated authorized client |
| `title`, `description` | Human-readable detail |
| `evidence` | JSON probe output |
| `status` | Triage workflow state |
| `kev`, `epss` | Enrichment when intel enabled |

**Principle:** Findings originate from **live probes only**. Agent-required engines produce honest empty or informational states — never synthetic vulnerabilities.

---

## Command Center surfaces

| Path | Purpose |
|------|---------|
| `/command-center/findings` | Global findings command center |
| Engine hub panels | Per-engine finding lists |
| Client dashboard | Client-scoped findings |
| `/command-center/reports` | Report generation and history |

UI audit script `scripts/weissman-ui-audit.mjs` verifies every page exposes refresh, export, and search on list surfaces.

---

## Step-by-step: triage workflow

### 1. Open Findings Command Center

Filter by client, severity, engine, status, or date range.

Use global search toolbar for keyword lookup across titles and evidence.

### 2. Review and validate

For each finding:

- Confirm target was in authorized scope
- Distinguish true positive vs false positive
- Check KEV badge (CISA Known Exploited Vulnerabilities)
- Check EPSS score for prioritization

### 3. Update status

Standard workflow states:

| Status | Meaning |
|--------|---------|
| `open` | New, unreviewed |
| `confirmed` | Validated true positive |
| `false_positive` | Not actionable |
| `accepted_risk` | Acknowledged with business sign-off |
| `remediated` | Fix verified |
| `closed` | Final state |

Analyst+ role required for status mutations.

### 4. Add analyst notes

Document reasoning, ticket IDs, and remediation guidance. Notes append to audit trail.

### 5. Bulk operations

Select multiple findings for batch status update or export. Use with care — bulk confirm requires operator review.

---

## Report generation

### PDF reports

Command Center → **Reports** → Generate

Includes:

- Executive summary
- Findings by severity
- Scope and ROE reference
- Scan metadata and timestamps

Suitable for customer delivery and compliance archives.

### CSV export

Findings list → **Export CSV**

Columns: id, client, engine, severity, status, title, target, timestamps, KEV/EPSS.

Use for SIEM ingestion, ticketing integration, or spreadsheet analysis.

### Crypto proof artifacts

Selected engines produce verifiable proof bundles (hash-chained evidence). Store with engagement records for dispute resolution.

---

## Threat intel enrichment

Background workers refresh:

- **CISA KEV** catalog (`WEISSMAN_INTEL_KEV_ENABLED`, default on)
- **FIRST EPSS** scores (`WEISSMAN_INTEL_EPSS_ENABLED`, default on)

Findings matching CVE IDs auto-display enrichment badges. Disable only in air-gapped deployments with local mirror.

---

## Integration with alerting

Critical findings may trigger alert rules (manual 15) based on severity, KEV presence, or engine type.

SOAR playbooks can auto-create tickets from new `confirmed` findings.

---

## Verification

```bash
# List findings API
curl -sf -b cookies.txt 'https://localhost/api/findings?limit=10' | jq '.findings | length'

# Export endpoint (if exposed)
# Generate PDF from UI and confirm file downloads

# Intel enrichment spot-check
curl -sf -b cookies.txt 'https://localhost/api/findings?severity=critical' | jq '.findings[0].kev'
```

Manual checklist:

- [ ] Finding from test scan visible with correct severity
- [ ] Status change persists after refresh
- [ ] CSV export opens in spreadsheet tool
- [ ] PDF includes client name and scope footer
- [ ] KEV/EPSS badges appear for CVE-backedlinked findings

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Duplicate findings | Expected dedup by signature — merge in triage |
| Missing KEV data | Check intel worker logs; verify `WEISSMAN_INTEL_KEV_ENABLED` |
| Export empty | Filter too restrictive; confirm findings exist for client |
| PDF generation fails | Check server logs; disk space on worker node |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [15-alerting-soar-ai](15-alerting-soar-ai.md)
- [18-qa-verification](18-qa-verification.md)
