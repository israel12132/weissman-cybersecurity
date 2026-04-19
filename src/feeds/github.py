"""GitHub Security Advisories feed."""
import requests
from datetime import datetime

from src.models import Finding, FindingType, Severity
from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT
from .base import BaseFeed, FeedResult


class GitHubFeed(BaseFeed):
    source_name = "github"
    URL = "https://api.github.com/advisories"

    def __init__(self, token: str = ""):
        self.token = token
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/vnd.github+json"
        self.session.headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def fetch(self) -> FeedResult:
        findings = []
        try:
            params = {"per_page": 50, "sort": "updated", "direction": "desc"}
            r = get_with_retry(self.session, self.URL, params=params, timeout=ENTERPRISE_HTTP_TIMEOUT)
            r.raise_for_status()
            for adv in r.json():
                ghsa_id = adv.get("ghsa_id", "")
                summary = adv.get("summary") or adv.get("description", "")[:200]
                severity = (adv.get("severity") or "medium").lower()
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                refs = [adv.get("html_url", "")] if adv.get("html_url") else []
                refs.extend([u.get("value") for u in adv.get("references", []) if u.get("value")])
                # GitHub Advisory API: cve_ids is a list of CVE ID strings.
                cves = [c for c in (adv.get("cve_ids") or []) if isinstance(c, str) and c]
                if cves:
                    refs = cves + refs
                ecosystem = adv.get("ecosystem", "") or "unknown"
                package = adv.get("package", {}).get("name", "") or "unknown"
                finding = Finding(
                    id=ghsa_id or adv.get("id", "unknown"),
                    type=FindingType.ADVISORY,
                    title=adv.get("summary", ghsa_id) or ghsa_id,
                    description=summary,
                    severity=sev_map.get(severity, Severity.MEDIUM),
                    source=self.source_name,
                    source_id=ghsa_id,
                    references=refs[:5],
                    affected_components=[f"{ecosystem}:{package}"],
                    published_at=datetime.fromisoformat(adv.get("published_at", "").replace("Z", "+00:00")) if adv.get("published_at") else None,
                    raw={"cve_ids": cves},
                )
                findings.append(finding)
        except Exception as e:
            return FeedResult([], self.source_name, str(e))
        return FeedResult(findings, self.source_name)
