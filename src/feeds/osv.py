"""OSV (Open Source Vulnerabilities) feed. Uses modified_id.csv for recent vulns."""
import csv
import io
from datetime import datetime

from src.models import Finding, FindingType, Severity
from src.http_client import safe_get, ENTERPRISE_HTTP_TIMEOUT
from .base import BaseFeed, FeedResult

OSV_MODIFIED_CSV = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


def _severity_from_osv(v: dict) -> Severity:
    """
    Resolve severity from OSV record. Priority:
    1. severity[] array with CVSS score (most precise).
    2. database_specific.severity string.
    Falls back to MEDIUM when nothing matches.
    """
    for sev_entry in v.get("severity") or []:
        score_str = sev_entry.get("score") or ""
        # CVSS3 vector → extract base score from last digit cluster is unreliable; try numeric directly.
        sev_type = (sev_entry.get("type") or "").upper()
        if sev_type in ("CVSS_V3", "CVSS_V2"):
            # OSV CVSS score may be a vector string like "CVSS:3.1/…/7.5" or numeric.
            # Try to extract the trailing numeric part.
            parts = score_str.split("/")
            for part in reversed(parts):
                try:
                    numeric = float(part)
                    from .base import BaseFeed as _B
                    return _B._severity_from_cvss(numeric)
                except ValueError:
                    continue
    db_sev = (v.get("database_specific") or {}).get("severity") or ""
    if db_sev:
        return getattr(Severity, db_sev.upper(), Severity.MEDIUM)
    return Severity.MEDIUM


class OSVFeed(BaseFeed):
    source_name = "osv"

    def fetch(self) -> FeedResult:
        findings = []
        try:
            r = safe_get(OSV_MODIFIED_CSV, timeout=ENTERPRISE_HTTP_TIMEOUT)
            reader = csv.reader(io.StringIO(r.text))
            ids = [row[0] for row in reader if row][1:21]  # skip header, take 20 recent

            for vid in ids:
                try:
                    vr = safe_get(f"{OSV_VULN_URL}/{vid}", timeout=ENTERPRISE_HTTP_TIMEOUT)
                except Exception:
                    continue
                if vr.status_code != 200:
                    continue
                v = vr.json()
                vid = v.get("id", "unknown")
                summary = (v.get("summary") or v.get("details", "") or "")[:300]
                refs = [x.get("url") for x in v.get("references", []) if x.get("url")]
                if v.get("database_specific", {}).get("url"):
                    refs.insert(0, v["database_specific"]["url"])
                severity = _severity_from_osv(v)
                affected = []
                for a in v.get("affected", []):
                    pkg = a.get("package", {})
                    affected.append(f"{pkg.get('ecosystem', '')}:{pkg.get('name', '')}")
                finding = Finding(
                    id=vid,
                    type=FindingType.CVE if "CVE-" in vid or "GHSA-" in vid else FindingType.ADVISORY,
                    title=vid + ": " + (summary[:60] + "..." if len(summary) > 60 else summary),
                    description=summary,
                    severity=severity,
                    source=self.source_name,
                    source_id=vid,
                    references=refs[:5],
                    affected_components=affected or ["unknown"],
                    published_at=datetime.fromisoformat(v.get("published", "").replace("Z", "+00:00")) if v.get("published") else None,
                    raw={},
                )
                findings.append(finding)
        except Exception as e:
            return FeedResult([], self.source_name, str(e))
        return FeedResult(findings, self.source_name)
