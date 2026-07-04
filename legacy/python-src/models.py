"""Shared data models for findings and intel.
Zero False Positives: tech_stack is strictly List[str]; word-boundary matching; short-name filter.
"""
import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# Allowed tech names with length < 3 (avoid garbage like "in", "act" from nginx/react)
ALLOWED_SHORT_TECH = frozenset({"go", "os", "c", "js", "wp", "py", "ts", "rb", "php"})


def normalize_tech_stack_to_list(tech_stack: Any) -> list[str]:
    """Ensure tech_stack is List[str]: split comma-separated string, strip, filter short/garbage."""
    if tech_stack is None:
        return []
    if isinstance(tech_stack, str):
        tech_stack = [t.strip() for t in tech_stack.split(",") if t and t.strip()]
    out: list[str] = []
    for t in tech_stack or []:
        if not isinstance(t, str):
            continue
        s = t.strip().lower()
        if not s:
            continue
        if len(s) >= 3 or s in ALLOWED_SHORT_TECH:
            out.append(s)
    return list(dict.fromkeys(out))


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    CVE = "cve"
    BREACH = "breach"
    THREAT_INTEL = "threat_intel"
    ADVISORY = "advisory"
    OTHER = "other"


class Finding(BaseModel):
    id: str
    type: FindingType
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    source: str  # e.g. "nvd", "github", "osv", "otx", "hibp"
    source_id: str = ""  # CVE-ID, advisory URL, etc.
    references: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)  # e.g. "nginx", "wordpress"
    published_at: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def matches_tech_stack(self, tech_stack: list[str]) -> bool:
        stack = normalize_tech_stack_to_list(tech_stack)
        return len(self.matched_tech_stack(stack)) > 0 or (not stack)

    def matched_tech_stack(self, tech_stack: list[str]) -> list[str]:
        """Returns which tech_stack items matched this finding. Word-boundary only (no substring)."""
        stack = normalize_tech_stack_to_list(tech_stack)
        if not stack:
            return []
        matched: list[str] = []
        for comp in self.affected_components:
            c = (comp or "").lower()
            if not c or c == "unknown":
                continue
            for s in stack:
                # Word-boundary match only: "nginx" must not match "in" or "act" from "react"
                try:
                    if re.search(r"\b" + re.escape(s) + r"\b", c) or re.search(r"\b" + re.escape(c) + r"\b", s):
                        matched.append(s)
                        break
                    # Explicit aliases (python/pypi, node/npm/nodejs)
                    if {s, c} <= {"python", "pypi"} or {s, c} <= {"node", "npm", "nodejs"}:
                        matched.append(s)
                        break
                except re.error:
                    if s == c:
                        matched.append(s)
                        break
        return list(dict.fromkeys(matched))


class ClientFinding(BaseModel):
    client_id: str
    finding: Finding
    relevance_note: str = ""  # why this applies to the client
