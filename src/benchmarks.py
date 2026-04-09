"""
Weissman-cybersecurity: C-level industry benchmarking.
Compares client Weissman Score and EPSS to sector averages (Finance, Tech, Automotive)
for executive reporting and Command Center UI.
"""
from __future__ import annotations

from typing import Any

# Reference sector averages (based on aggregated security surveys and feed data).
# Used for PDF and Command Center "vs competitors" view.
SECTOR_AVERAGES: dict[str, dict[str, Any]] = {
    "finance": {
        "name": "Financial Services",
        "weissman_score_avg": 68,
        "epss_avg": 0.12,
        "description": "Banks, insurance, asset management",
    },
    "tech": {
        "name": "Technology / SaaS",
        "weissman_score_avg": 74,
        "epss_avg": 0.08,
        "description": "Software, cloud, infrastructure",
    },
    "automotive": {
        "name": "Automotive / Manufacturing",
        "weissman_score_avg": 71,
        "epss_avg": 0.10,
        "description": "OEMs, suppliers, connected vehicles",
    },
    "healthcare": {
        "name": "Healthcare",
        "weissman_score_avg": 65,
        "epss_avg": 0.14,
        "description": "Providers, pharma, health tech",
    },
    "retail": {
        "name": "Retail / E‑commerce",
        "weissman_score_avg": 70,
        "epss_avg": 0.11,
        "description": "Retail, hospitality, e‑commerce",
    },
}

DEFAULT_SECTOR = "tech"


def get_industry_benchmarks(sector: str | None = None) -> list[dict[str, Any]]:
    """
    Return benchmark rows for all sectors (or the given sector).
    Each row: sector key, name, weissman_score_avg, epss_avg, description.
    """
    sector = (sector or "").strip().lower() or None
    if sector and sector in SECTOR_AVERAGES:
        s = SECTOR_AVERAGES[sector]
        return [{"sector": sector, **s}]
    return [
        {"sector": k, **v}
        for k, v in SECTOR_AVERAGES.items()
    ]


def get_benchmark_comparison(
    client_score: int,
    sector: str | None = None,
    client_epss_avg: float | None = None,
) -> dict[str, Any]:
    """
    Compare client's Weissman Score (and optional EPSS) to sector and all sectors.
    Returns: sector, sector_avg_score, vs_sector (above/below/equal), percentile_rank,
             all_sectors (list of sector vs client), recommendation.
    """
    client_score = max(0, min(100, int(client_score)))
    sector = (sector or "").strip().lower() or DEFAULT_SECTOR
    ref = SECTOR_AVERAGES.get(sector, SECTOR_AVERAGES[DEFAULT_SECTOR])
    sector_avg = ref["weissman_score_avg"]
    sector_name = ref["name"]

    if client_score > sector_avg:
        vs_sector = "above"
        vs_label = f"Above {sector_name} average"
    elif client_score < sector_avg:
        vs_sector = "below"
        vs_label = f"Below {sector_name} average"
    else:
        vs_sector = "equal"
        vs_label = f"At {sector_name} average"

    # Simple percentile: assume sector scores are roughly 50–85; client 0–100.
    all_scores = [s["weissman_score_avg"] for s in SECTOR_AVERAGES.values()]
    all_scores.append(client_score)
    all_scores.sort()
    idx = all_scores.index(client_score)
    percentile_rank = round((idx / (len(all_scores) - 1)) * 100) if len(all_scores) > 1 else 50
    percentile_rank = max(1, min(99, percentile_rank))

    all_sectors = []
    for k, v in SECTOR_AVERAGES.items():
        avg = v["weissman_score_avg"]
        diff = client_score - avg
        all_sectors.append({
            "sector": k,
            "name": v["name"],
            "avg_score": avg,
            "vs_client": "above" if avg > client_score else "below" if avg < client_score else "equal",
            "diff": diff,
        })

    if client_score >= 90:
        recommendation = "Strong posture. Continue monitoring and maintain remediation cadence."
    elif client_score >= 70:
        recommendation = "Targeted remediation recommended. Address High/Critical findings to reach top quartile."
    else:
        recommendation = "Prioritize Critical and High findings. Consider accelerated patch cycle to align with sector norms."

    return {
        "sector": sector,
        "sector_name": sector_name,
        "sector_avg_score": sector_avg,
        "client_score": client_score,
        "vs_sector": vs_sector,
        "vs_label": vs_label,
        "percentile_rank": percentile_rank,
        "all_sectors": all_sectors,
        "recommendation": recommendation,
        "client_epss_avg": client_epss_avg,
        "sector_epss_avg": ref.get("epss_avg"),
    }
