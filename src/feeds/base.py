from abc import ABC, abstractmethod
from datetime import datetime

from src.models import Finding, FindingType, Severity


class FeedResult:
    def __init__(self, findings: list[Finding], source: str, error: str | None = None):
        self.findings = findings
        self.source = source
        self.error = error


class BaseFeed(ABC):
    source_name: str = "base"

    @abstractmethod
    def fetch(self) -> FeedResult:
        """Fetch latest vulnerabilities/intel from this source."""
        pass

    @staticmethod
    def _severity_from_cvss(score: float | None) -> Severity:
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO
