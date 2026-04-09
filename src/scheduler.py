"""Hourly run: fetch intel, correlate to clients, generate report."""
from pathlib import Path

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config import load_config
from src.correlation import correlate_findings_to_clients, dedupe_by_finding_id
from src.reports import run_report


def job(config_path: str = "config.yaml") -> None:
    config = load_config(config_path)
    client_findings = correlate_findings_to_clients(config_path)
    client_findings = dedupe_by_finding_id(client_findings)
    out_dir = Path(config.reporting.output_dir)
    run_report(
        client_findings,
        out_dir,
        config.reporting.format,
        config.reporting.timezone,
    )
    print(f"Report written to {out_dir} ({len(client_findings)} findings)")


def run_hourly(config_path: str = "config.yaml") -> None:
    config = load_config(config_path)
    scheduler = BlockingScheduler()
    scheduler.add_job(
        job,
        trigger=IntervalTrigger(hours=config.scheduler.check_interval_hours),
        id="hourly_report",
        kwargs={"config_path": config_path},
    )
    job(config_path)  # run once immediately
    scheduler.start()
