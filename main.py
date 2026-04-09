#!/usr/bin/env python3
"""
Security Assessment Bot - Run vulnerability intel correlation and reports.
Usage:
  python main.py              # Single run, write report
  python main.py --hourly     # Run every hour (default 1h interval)
  python main.py --config ./config.yaml
"""
from pathlib import Path

import typer

from src.config import load_config
from src.correlation import correlate_findings_to_clients, dedupe_by_finding_id
from src.reports import run_report
from src.scheduler import run_hourly

app = typer.Typer()


@app.callback(invoke_without_command=True)
def run(
    ctx: typer.Context,
    config_path: Path = typer.Option(Path("config.yaml"), "--config", "-c", help="Config file"),
    hourly: bool = typer.Option(False, "--hourly", "-H", help="Run every hour"),
) -> None:
    config_path = config_path.resolve()
    if not config_path.exists():
        typer.echo(f"Config not found: {config_path}. Copy config.example.yaml to config.yaml")
        raise typer.Exit(1)
    if hourly:
        run_hourly(str(config_path))
    else:
        client_findings = correlate_findings_to_clients(str(config_path))
        client_findings = dedupe_by_finding_id(client_findings)
        cfg = load_config(config_path)
        written = run_report(
            client_findings,
            cfg.reporting.output_dir,
            cfg.reporting.format,
            cfg.reporting.timezone,
        )
        typer.echo(f"Done. {len(client_findings)} findings → {[str(p) for p in written]}")


if __name__ == "__main__":
    app()
