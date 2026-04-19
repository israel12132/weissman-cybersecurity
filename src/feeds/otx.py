"""AlienVault OTX (Open Threat Exchange) pulse feed."""
import requests
from datetime import datetime

from src.models import Finding, FindingType, Severity
from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT
from .base import BaseFeed, FeedResult


class OTXFeed(BaseFeed):
    source_name = "otx"
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers["X-OTX-API-KEY"] = api_key or ""

    def fetch(self) -> FeedResult:
        findings = []
        if not self.api_key:
            return FeedResult([], self.source_name, "OTX API key not set")
        try:
            r = get_with_retry(self.session, f"{self.BASE}/pulses/subscribed", params={"limit": 30}, timeout=ENTERPRISE_HTTP_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            for p in data.get("results", []):
                pid = p.get("id", "unknown")
                name = p.get("name", pid)
                desc = (p.get("description", "") or "")[:300]
                refs = [p.get("url", "")] if p.get("url") else []
                # Tags in OTX pulses are plain strings; no "indicator" dict key.
                tags = [str(t).lower() for t in p.get("tags", []) if t]
                # Map OTX severity-like to our Severity
                severity = Severity.MEDIUM
                if "critical" in tags or "ransomware" in tags:
                    severity = Severity.CRITICAL
                elif "malware" in tags or "high" in tags:
                    severity = Severity.HIGH
                finding = Finding(
                    id=str(pid),
                    type=FindingType.THREAT_INTEL,
                    title=name,
                    description=desc,
                    severity=severity,
                    source=self.source_name,
                    source_id=str(pid),
                    references=refs[:5],
                    affected_components=(tags[:5] if tags else ["threat"]),
                    published_at=datetime.fromisoformat(p.get("created", "").replace("Z", "+00:00")) if p.get("created") else None,
                    raw={"author": p.get("author_name")},
                )
                findings.append(finding)
        except Exception as e:
            return FeedResult([], self.source_name, str(e))
        return FeedResult(findings, self.source_name)
