"""Have I Been Pwned - breach/domain check. Use only for authorized client domains."""
import requests
from datetime import datetime

from src.models import Finding, FindingType, Severity
from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT
from .base import BaseFeed, FeedResult


class HIBPFeed(BaseFeed):
    source_name = "hibp"
    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers["hibp-api-key"] = api_key
        self.session.headers["User-Agent"] = "SecurityAssessmentBot"

    def check_breaches_for_domain(self, domain: str) -> list[Finding]:
        """Check if a domain (authorized scope) appears in breaches. Call only for client-authorized domains."""
        findings = []
        if not self.api_key:
            return findings
        try:
            r = get_with_retry(self.session, f"{self.BASE}/breacheddomain/{domain}", timeout=ENTERPRISE_HTTP_TIMEOUT)
            if r.status_code == 404:
                return findings
            r.raise_for_status()
            breaches = r.json() if r.content else []
            for b in breaches:
                name = b.get("Name", "")
                desc = (b.get("Description", "") or "")[:300]
                breach_date = b.get("BreachDate", "")
                # Build a useful reference URL: HIBP breach detail page when available.
                breach_domain = b.get("Domain", "")
                refs = []
                if breach_domain:
                    refs.append(f"https://haveibeenpwned.com/PwnedWebsites#{breach_domain}")
                if breach_date:
                    refs.append(breach_date)
                finding = Finding(
                    id=f"hibp-{name}-{domain}",
                    type=FindingType.BREACH,
                    title=f"Breach: {name} (domain {domain})",
                    description=desc,
                    severity=Severity.HIGH if b.get("IsSensitive") else Severity.MEDIUM,
                    source=self.source_name,
                    source_id=name,
                    references=refs,
                    affected_components=[domain, name],
                    published_at=datetime.strptime(breach_date, "%Y-%m-%d") if breach_date else None,
                    raw=b,
                )
                findings.append(finding)
        except Exception:
            pass
        return findings

    def fetch(self) -> FeedResult:
        """Fetch returns empty - HIBP is used per-domain in the correlation step for client domains only."""
        return FeedResult([], self.source_name)
