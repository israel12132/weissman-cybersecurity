"""NVD (National Vulnerability Database) - CVE feed."""
import logging
import os
import requests
from datetime import datetime, timedelta

from src.models import Finding, FindingType, Severity
from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT
from .base import BaseFeed, FeedResult

logger = logging.getLogger(__name__)

# Max CVEs to fetch per run; increase via NVD_MAX_RESULTS env var (cap: 2000).
_NVD_MAX_RESULTS = min(int(os.getenv("NVD_MAX_RESULTS", "400")), 2000)
_NVD_PAGE_SIZE = 200  # NVD max per request


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
            start_index = 0
            total_fetched = 0

            while total_fetched < _NVD_MAX_RESULTS:
                page_size = min(_NVD_PAGE_SIZE, _NVD_MAX_RESULTS - total_fetched)
                params = {
                    "pubStartDate": start,
                    "pubEndDate": end,
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                }
                r = get_with_retry(self.session, self.BASE, params=params, timeout=ENTERPRISE_HTTP_TIMEOUT)
                r.raise_for_status()
                data = r.json()
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for item in vulnerabilities:
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
                        if score is not None:
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

                total_fetched += len(vulnerabilities)
                start_index += len(vulnerabilities)
                if start_index >= total_results or len(vulnerabilities) < page_size:
                    break  # no more pages

        except Exception as e:
            logger.warning("NVD feed error: %s", e)
            return FeedResult(findings or [], self.source_name, str(e))
        return FeedResult(findings, self.source_name)
