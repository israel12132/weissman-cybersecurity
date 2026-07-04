"""Generate hourly and on-demand reports (HTML, JSON)."""
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from src.models import ClientFinding, Severity


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _sort_findings(cf_list: list[ClientFinding]) -> list[ClientFinding]:
    return sorted(
        cf_list,
        key=lambda cf: (SEVERITY_ORDER.index(cf.finding.severity), cf.finding.id),
    )


def report_by_client(client_findings: list[ClientFinding]) -> dict[str, list[ClientFinding]]:
    by_client: dict[str, list[ClientFinding]] = {}
    for cf in client_findings:
        by_client.setdefault(cf.client_id, []).append(cf)
    for k in by_client:
        by_client[k] = _sort_findings(by_client[k])
    return by_client


def generate_json_report(
    client_findings: list[ClientFinding],
    output_path: Path,
    timezone: str = "Asia/Jerusalem",
) -> None:
    by_client = report_by_client(client_findings)
    tz = ZoneInfo(timezone)
    payload = {
        "generated_at": datetime.now(tz).isoformat(),
        "summary": {
            "total_findings": len(client_findings),
            "clients_affected": len(by_client),
            "by_severity": {
                s.value: sum(1 for cf in client_findings if cf.finding.severity == s)
                for s in Severity
            },
        },
        "by_client": {
            cid: [
                {
                    "finding_id": cf.finding.id,
                    "type": cf.finding.type.value,
                    "title": cf.finding.title,
                    "severity": cf.finding.severity.value,
                    "source": cf.finding.source,
                    "relevance": cf.relevance_note,
                    "references": cf.finding.references,
                }
                for cf in findings
            ]
            for cid, findings in by_client.items()
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_html_report(
    client_findings: list[ClientFinding],
    output_path: Path,
    timezone: str = "Asia/Jerusalem",
) -> None:
    by_client = report_by_client(client_findings)
    tz = ZoneInfo(timezone)
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M")

    rows = []
    for cid, findings in by_client.items():
        for cf in findings:
            rows.append(
                f"""
                <tr>
                    <td>{cid}</td>
                    <td><span class="badge severity-{cf.finding.severity.value}">{cf.finding.severity.value}</span></td>
                    <td>{cf.finding.type.value}</td>
                    <td>{cf.finding.source}</td>
                    <td><strong>{cf.finding.id}</strong></td>
                    <td>{cf.finding.title[:80] + ('...' if len(cf.finding.title) > 80 else '')}</td>
                    <td>{cf.relevance_note[:60] + ('...' if len(cf.relevance_note) > 60 else '')}</td>
                </tr>
                """
            )

    summary = {
        s.value: sum(1 for cf in client_findings if cf.finding.severity == s)
        for s in Severity
    }

    html = f"""
<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>דוח אבטחה - {now}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #0f3460; }}
        .meta {{ color: #888; margin-bottom: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #333; padding: 10px; text-align: right; }}
        th {{ background: #16213e; }}
        tr:nth-child(even) {{ background: #1f2b3d; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .severity-critical {{ background: #c0392b; }}
        .severity-high {{ background: #e74c3c; }}
        .severity-medium {{ background: #f39c12; }}
        .severity-low {{ background: #3498db; }}
        .severity-info {{ background: #95a5a6; }}
        .summary {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
        .summary span {{ background: #16213e; padding: 8px 16px; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>דוח ממצאי אבטחה</h1>
    <p class="meta">נוצר: {now} | סה"כ ממצאים: {len(client_findings)} | לקוחות מושפעים: {len(by_client)}</p>
    <div class="summary">
        <span>Critical: {summary.get("critical", 0)}</span>
        <span>High: {summary.get("high", 0)}</span>
        <span>Medium: {summary.get("medium", 0)}</span>
        <span>Low: {summary.get("low", 0)}</span>
    </div>
    <table>
        <thead>
            <tr>
                <th>לקוח</th>
                <th>חומרה</th>
                <th>סוג</th>
                <th>מקור</th>
                <th>מזהה</th>
                <th>כותרת</th>
                <th>רלוונטיות</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
</body>
</html>
"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def run_report(
    client_findings: list[ClientFinding],
    output_dir: str | Path,
    formats: list[str],
    timezone: str = "Asia/Jerusalem",
) -> list[Path]:
    output_dir = Path(output_dir)
    tz = ZoneInfo(timezone)
    stamp = datetime.now(tz).strftime("%Y-%m-%d_%H-%M")
    written: list[Path] = []
    if "json" in formats:
        p = output_dir / f"report_{stamp}.json"
        generate_json_report(client_findings, p, timezone)
        written.append(p)
    if "html" in formats:
        p = output_dir / f"report_{stamp}.html"
        generate_html_report(client_findings, p, timezone)
        written.append(p)
    return written
