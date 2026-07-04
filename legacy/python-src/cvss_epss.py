"""
Weissman-cybersecurity Enterprise: CVSS 3.1 vector and EPSS (Exploit Prediction Scoring).
"""
import logging


from src.http_client import safe_get, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"

# CVSS v3.1 metric value → numeric impact (from spec)
_CVSS_IMPACT = {"N": 0.00, "L": 0.22, "H": 0.56}
_CVSS_SCORE_TABLE: dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "informational": 0.5,
    "info": 0.5,
}


def severity_to_cvss_vector(severity: str) -> str:
    """
    Map severity to a minimal CVSS 3.1 vector string.
    Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:X/I:X/A:X
    """
    s = (severity or "medium").lower()
    if s == "critical":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if s == "high":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if s == "medium":
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    if s == "low":
        return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"
    return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


def parse_cvss_vector(vector: str) -> float | None:
    """
    Parse a CVSS v3.x vector string and return a base score (0.0–10.0).

    Supports the simplified vectors produced by :func:`severity_to_cvss_vector`
    as well as arbitrary CVSS:3.0/3.1 vectors. Returns ``None`` when the vector
    is malformed or does not contain enough metrics to compute a score.

    Algorithm follows CVSS v3.1 specification (simplified — accounts for
    Confidentiality, Integrity, Availability impact and Attack Vector only).
    """
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None

    # Parse key:value pairs
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

    if not metrics:
        return None

    # Determine ISCBase from C, I, A
    c_val = _CVSS_IMPACT.get(metrics.get("C", "L"), 0.33)
    i_val = _CVSS_IMPACT.get(metrics.get("I", "L"), 0.33)
    a_val = _CVSS_IMPACT.get(metrics.get("A", "N"), 0.0)
    isc_base = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)

    scope_changed = metrics.get("S", "U") == "C"
    if scope_changed:
        iss = 7.52 * isc_base - 3.25 * (isc_base - 0.02) ** 15
    else:
        iss = 6.42 * isc_base

    if iss <= 0:
        return 0.0

    # Exploitability sub-score
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_map_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
    pr_map_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
    ui_map = {"N": 0.85, "R": 0.62}

    av = av_map.get(metrics.get("AV", "N"), 0.85)
    ac = ac_map.get(metrics.get("AC", "L"), 0.77)
    pr_map = pr_map_changed if scope_changed else pr_map_unchanged
    pr = pr_map.get(metrics.get("PR", "N"), 0.85)
    ui = ui_map.get(metrics.get("UI", "N"), 0.85)
    esc = 8.22 * av * ac * pr * ui

    if scope_changed:
        base = min(10.0, 1.08 * (iss + esc))
    else:
        base = min(10.0, iss + esc)

    # Round up to 1 decimal per spec
    import math
    return math.ceil(base * 10) / 10.0


def get_epss_score(cve_id: str) -> float | None:
    """Fetch EPSS (0-1) for CVE from API. Returns None on failure."""
    if not cve_id or not cve_id.strip().upper().startswith("CVE-"):
        return None
    try:
        r = safe_get(EPSS_API, params={"cve": cve_id.strip()}, timeout=ENTERPRISE_HTTP_TIMEOUT)
        if r.status_code != 200:
            return None
        data = r.json()
        for item in (data.get("data") or [])[:1]:
            return float(item.get("epss", 0) or 0)
        return None
    except Exception as e:
        logger.debug("EPSS fetch failed for %s: %s", cve_id, e)
        return None


def cvss_severity_to_numeric(severity: str) -> float:
    """Map severity to numeric (0-10) for scoring. Uses CVSS v3.1 midpoint values."""
    s = (severity or "medium").lower()
    return _CVSS_SCORE_TABLE.get(s, _CVSS_SCORE_TABLE["medium"])


def weissman_priority_score(
    cvss_value: float | None = None,
    severity: str | None = None,
    epss_value: float | None = None,
    asset_criticality: float = 1.0,
    vector: str | None = None,
) -> float:
    """
    Weissman Priority Score — a risk-adjusted composite metric.

    Formula:  ``score = CVSS × EPSS_weight × criticality_factor``

    Where:
    * ``CVSS`` is the base CVSS score (0–10). Resolved via *cvss_value*,
      *vector* (parsed), or *severity* (mapped), in that priority order.
    * ``EPSS_weight`` is a non-linear amplifier: exploits with high EPSS
      probability (≥ 0.5) are up-weighted aggressively; low-probability
      (< 0.1) are down-weighted. Formula: ``0.3 + 1.4 × epss``.
    * ``criticality_factor`` clips to [0.5, 2.0].
    * Final score is scaled to 0–100 and rounded to 2 decimal places.

    Parameters
    ----------
    cvss_value:
        Explicit CVSS base score (0–10).
    severity:
        Textual severity ("critical", "high", "medium", "low").
    epss_value:
        EPSS probability (0–1); defaults to 0.1 when omitted.
    asset_criticality:
        Multiplier for target importance (0.5 = low, 1.0 = normal, 2.0 = critical).
    vector:
        CVSS v3.x vector string — parsed to obtain a numeric score if
        *cvss_value* is not supplied.
    """
    # Resolve CVSS numeric
    cvss = cvss_value
    if cvss is None and vector:
        cvss = parse_cvss_vector(vector)
    if cvss is None and severity:
        cvss = cvss_severity_to_numeric(severity)
    if cvss is None:
        cvss = cvss_severity_to_numeric("medium")
    cvss = max(0.0, min(10.0, float(cvss)))

    # Resolve EPSS
    epss = float(epss_value) if epss_value is not None else 0.1
    epss = max(0.0, min(1.0, epss))

    criticality = max(0.5, min(2.0, float(asset_criticality)))

    # Non-linear EPSS weight: low base + steep slope
    epss_weight = 0.3 + 1.4 * epss  # range [0.3, 1.7]

    raw = cvss * epss_weight * criticality  # max ≈ 10 × 1.7 × 2.0 = 34
    # Scale so that a CVSS-10 / EPSS-1.0 / criticality-2.0 → 100
    score = (raw / 34.0) * 100.0
    return round(min(100.0, score), 2)
