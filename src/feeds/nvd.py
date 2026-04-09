"""NVD (National Vulnerability Database) - CVE feed."""
import requests
from datetime import datetime, timedelta

from src.models import Finding, FindingType, Severity
from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT
from .base import BaseFeed, FeedResult


class NVDFeed(BaseFeed):
    source_name = "nvd"
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers["apiKey"] = api_key

    def fetch(self) -> FeedResult:
        findings = []
        try:
            now = datetime.utcnow()
            start = (now - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000")
            end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
            params = {"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 200}
            r = get_with_retry(self.session, f"{self.BASE}", params=params, timeout=ENTERPRISE_HTTP_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "unknown")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                score = None
                for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for m in metrics.get(k, []):
                        if "cvssData" in m:
                            score = m["cvssData"].get("baseScore")
                            break
                refs = [u.get("url", "") for u in cve.get("references", []) if u.get("url")]
                configs = cve.get("configurations", [])
                affected = []
                for cfg in configs:
                    for node in cfg.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            criteria = match.get("criteria", "")
                            if ":" in criteria:
                                parts = criteria.split(":")
                                if len(parts) >= 5:
                                    affected.append(parts[4])  # product
                finding = Finding(
                    id=cve_id,
                    type=FindingType.CVE,
                    title=cve.get("id", "") + ": " + (desc[:80] + "..." if len(desc) > 80 else desc),
                    description=desc,
                    severity=self._severity_from_cvss(score),
                    source=self.source_name,
                    source_id=cve_id,
                    references=refs[:5],
                    affected_components=list(set(affected)) if affected else ["unknown"],
                    published_at=datetime.fromisoformat(cve.get("published", "").replace("Z", "+00:00")) if cve.get("published") else None,
                    raw={"metrics": metrics},
                )
                findings.append(finding)
        except Exception as e:
            return FeedResult([], self.source_name, str(e))
        return FeedResult(findings, self.source_name)
