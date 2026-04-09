"""
Weissman-cybersecurity: Background job logic (shared by APScheduler in-process or Celery workers).
Heavy tasks (orchestrator, discovery, supply chain, CVE check) run here for distributed scale.
"""
import json
import logging
import os
from datetime import datetime

from src.database import get_session_factory, ClientModel, ReportRunModel, VulnerabilityModel
from src.correlation import correlate_findings_from_db, dedupe_by_finding_id
from src.finding_validator import validate_findings
from src.delta_scan import has_changed as delta_has_changed, save_snapshot as delta_save_snapshot
from src.recon_engine import (
    get_new_assets_for_discovery_alert,
    normalized_asset_ids,
    run_full_recon,
)
from src import alerts
from src.darkweb_intel import run_darkweb_scan
from src.exploit_matcher import filter_matching_exploits
from src.threat_intel import fetch_exploit_repos_for_tech_stack, search_global_exploit_repos
from src.fingerprint import (
    fingerprint_ip_ranges,
    fingerprint_urls,
    run_fuzzer_binary,
    run_safe_probe,
)
from src.webhooks import build_webhook_payload, push_findings_to_webhooks
from src.supply_chain import run_supply_chain_scan
from src.secret_scan import run_secret_scan
from src.region_manager import should_process_tenant
from src.intel_harvester import harvest_and_merge

logger = logging.getLogger(__name__)


def _sync_run_findings_to_vulnerabilities(db, run_id: int, tenant_id: int | None, findings_serializable: list) -> None:
    """Insert vulnerability rows for lifecycle status. Call after creating a ReportRun."""
    try:
        run_created = datetime.utcnow()
        for item in findings_serializable or []:
            f = item.get("finding") or {}
            vid = f.get("id") or f.get("source_id") or f.get("title") or ""
            if not vid:
                continue
            rec = VulnerabilityModel(
                run_id=run_id,
                tenant_id=tenant_id,
                client_id=str(item.get("client_id") or ""),
                finding_id=str(vid)[:256],
                title=(f.get("title") or "")[:512],
                severity=(f.get("severity") or "medium")[:32],
                source=(f.get("source") or "")[:64],
                description=(f.get("description") or "")[:2000],
                status="OPEN",
                discovered_at=run_created,
            )
            db.add(rec)
        db.commit()
    except Exception as e:
        logger.warning("sync_run_findings_to_vulnerabilities failed: %s", e)


def auto_check_job() -> None:
    """
    Delta-scan: create report and alert ONLY when CVE set changed per client.
    """
    try:
        factory = get_session_factory()
        db = factory()
        try:
            clients = db.query(ClientModel).all()
            if not clients:
                return
            clients = [c for c in clients if should_process_tenant(c.tenant_id)]
            if not clients:
                return
            db_clients = [
                {"id": str(c.id), "name": c.name, "scope": c.to_scope_dict()}
                for c in clients
            ]
            client_findings = correlate_findings_from_db(db_clients)
            client_findings = dedupe_by_finding_id(client_findings)
            if not client_findings:
                return
            client_cve_ids = {}
            for cf in client_findings:
                fid = cf.finding.id or cf.finding.source_id or cf.finding.title or ""
                if fid:
                    client_cve_ids.setdefault(cf.client_id, []).append(fid)
            clients_with_changes = [
                cid for cid in client_cve_ids
                if delta_has_changed(cid, cve_ids=client_cve_ids[cid])
            ]
            if not clients_with_changes:
                return
            # Verified-only: run non-destructive PoC per finding; only include validated in report
            client_findings = validate_findings(client_findings, db_clients)
            by_severity = {}
            by_client = {}
            for cf in client_findings:
                by_severity[cf.finding.severity.value] = by_severity.get(cf.finding.severity.value, 0) + 1
                by_client[cf.client_id] = by_client.get(cf.client_id, 0) + 1
            findings_serializable = []
            for cf in client_findings:
                f = cf.finding
                findings_serializable.append({
                    "client_id": cf.client_id,
                    "relevance_note": cf.relevance_note,
                    "verified": True,
                    "finding": {
                        "id": f.id,
                        "type": f.type.value,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity.value,
                        "source": f.source,
                        "references": f.references,
                        "affected_components": f.affected_components,
                    },
                })
            try:
                from src.region_manager import get_current_region
                _region = get_current_region()
            except ImportError:
                _region = None
            run = ReportRunModel(
                findings_json=json.dumps(findings_serializable, default=str),
                summary=json.dumps({
                    "total": len(client_findings),
                    "by_severity": by_severity,
                    "by_client": by_client,
                }),
                region=_region or None,
            )
            db.add(run)
            db.commit()
            db.refresh(run)
            _sync_run_findings_to_vulnerabilities(db, run.id, None, findings_serializable)
            from src.datetime_utils import format_ist
            run_created = format_ist(run.created_at, short=True)
            if client_findings:
                try:
                    from pathlib import Path
                    from src.pdf_export import generate_report_pdf_auto
                    client_id_to_name = {str(c.id): (c.name or f"Client_{c.id}") for c in clients}
                    client_targets = {}
                    for c in clients:
                        doms = (c.domains or "[]")
                        try:
                            arr = json.loads(doms) if isinstance(doms, str) else doms
                        except Exception:
                            arr = []
                        first_d = next((d for d in arr if d and str(d).strip() and not str(d).startswith("*")), None)
                        if first_d:
                            u = str(first_d).strip()
                            if not u.startswith(("http://", "https://")):
                                u = f"https://{u}"
                            client_targets[str(c.id)] = u
                    path = generate_report_pdf_auto(
                        run.id,
                        run_created,
                        findings_serializable,
                        {"total": len(client_findings), "by_severity": by_severity, "by_client": by_client},
                        client_id_to_name,
                        tech_stack=list({t for c in clients for t in (c.to_scope_dict().get("tech_stack") or [])}),
                        client_targets=client_targets,
                    )
                    if path and path.exists():
                        run.pdf_path = f"reports/{path.name}"
                        db.commit()
                except Exception as e:
                    logger.warning("Auto-PDF for run %s failed: %s", run.id, e)
            try:
                payload = build_webhook_payload(
                    run.id,
                    run_created,
                    findings_serializable,
                    {"total": len(client_findings), "by_severity": by_severity, "by_client": by_client},
                )
                push_findings_to_webhooks(payload)
            except Exception as e:
                logger.warning("Webhook push failed: %s", e)
            for cf in client_findings:
                if cf.client_id not in clients_with_changes:
                    continue
                f = cf.finding
                if f.severity.value not in ("high", "critical"):
                    continue
                target = next((c.name for c in clients if str(c.id) == cf.client_id), cf.client_id)
                finding_id = f.id or f.source_id or f.title or ""
                msg = alerts.format_cve_alert(
                    target=target,
                    severity=f.severity.value,
                    title=f.title or f.id,
                    description=f.description or "",
                    source=f.source or "intel",
                )
                alerts.send_cve_alert_if_new(target, finding_id, msg)
            for cid, ids in client_cve_ids.items():
                delta_save_snapshot(cid, target_type="client", cve_ids=ids)
        finally:
            db.close()
    except Exception as e:
        logger.warning("auto_check_job error: %s", e)


def discovery_job() -> None:
    """Attack Surface Discovery & Shadow IT."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            clients = db.query(ClientModel).all()
        finally:
            db.close()
        if not clients:
            return
        clients = [c for c in clients if should_process_tenant(c.tenant_id)]
        for c in clients:
            try:
                scope = c.to_scope_dict()
                domains = [d for d in (scope.get("domains") or []) if d and not str(d).startswith("*")]
                tech_stack = list(scope.get("tech_stack") or [])
                keywords = [c.name] + tech_stack
                for domain in (domains or [])[:5]:
                    domain = (domain or "").strip().lower()
                    if not domain or "://" in domain:
                        domain = domain.split("://")[-1].split("/")[0]
                    if not domain:
                        continue
                    discovered = run_full_recon(
                        domain,
                        str(c.id),
                        c.name or "Client",
                        keywords=keywords,
                        use_ct=True,
                        use_dns_brute=True,
                        use_whois=True,
                        use_buckets=True,
                        use_gcp=True,
                        use_exposed_api=False,
                    )
                    new_assets = get_new_assets_for_discovery_alert(str(c.id), discovered)
                    for a in new_assets:
                        alerts.send_discovery_alert_if_new(
                            str(c.id),
                            c.name or "Client",
                            a.asset_type,
                            a.value,
                            a.confidence,
                        )
                    all_ids = normalized_asset_ids(discovered)
                    if all_ids:
                        delta_save_snapshot(str(c.id), target_type="client", assets=all_ids)
            except Exception as e:
                logger.warning("Discovery job error for client %s: %s", getattr(c, "name", "?"), e)
    except Exception as e:
        logger.warning("Discovery job error: %s", e)


def supply_chain_secret_job() -> None:
    """Supply chain + secret leak scan per client."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            clients = db.query(ClientModel).all()
        finally:
            db.close()
        if not clients:
            return
        clients = [c for c in clients if should_process_tenant(c.tenant_id)]
        for c in clients:
            try:
                org_name = (c.name or "").strip() or "Client"
                domain = None
                scope = c.to_scope_dict()
                domains = scope.get("domains") or []
                if domains:
                    domain = (domains[0] or "").strip().split("://")[-1].split("/")[0]
                run_supply_chain_scan(org_name, domain=domain, check_typosquat=True, check_compromised=True)
                run_secret_scan(org_name)
            except Exception as e:
                logger.warning("Supply chain/secret job error for %s: %s", getattr(c, "name", "?"), e)
    except Exception as e:
        logger.warning("Supply chain/secret job error: %s", e)


def autonomous_recon_fuzz_job() -> None:
    """Fingerprint first, then context-aware fuzzer: payloads strictly match detected tech (no Apache/PHP on IIS)."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            clients = db.query(ClientModel).all()
            if not clients:
                return
            clients = [c for c in clients if should_process_tenant(c.tenant_id)]
            port = os.getenv("PORT", "8000")
            notify_url = f"http://127.0.0.1:{port}/internal/fuzzer-report-created"
            for c in clients:
                scope = c.to_scope_dict()
                domains = [d for d in (scope.get("domains") or []) if d and not str(d).startswith("*")]
                ip_ranges = [r for r in (scope.get("ip_ranges") or []) if r and str(r).strip()]
                urls = []
                for d in domains:
                    d = (d or "").strip()
                    if not d:
                        continue
                    urls.append(d if d.startswith(("http://", "https://")) else f"https://{d}")
                if urls:
                    fp_result = fingerprint_urls(urls)
                    if fp_result:
                        for target_url, detected_tech in fp_result.items():
                            if detected_tech:
                                run_fuzzer_binary(
                                    target_url,
                                    notify_url=notify_url,
                                    tech_stack=detected_tech,
                                )
                            else:
                                run_fuzzer_binary(target_url, notify_url=notify_url, tech_stack=None)
                    else:
                        run_fuzzer_binary(urls[0], notify_url=notify_url, tech_stack=list(scope.get("tech_stack") or []) or None)
                if ip_ranges:
                    fingerprint_ip_ranges(ip_ranges[:10])
        finally:
            db.close()
    except Exception as e:
        logger.warning("autonomous_recon_fuzz_job error: %s", e)


def exploit_matching_job() -> None:
    """
    Global threat intel: fetch ALL exploit/PoC repos globally, then cross-reference
    each client's tech stack. If a global threat matches client infra → CRITICAL alert.
    Also runs client-scoped search for extra coverage.
    """
    try:
        factory = get_session_factory()
        db = factory()
        try:
            clients = db.query(ClientModel).all()
            clients = [c for c in clients if should_process_tenant(c.tenant_id)]
        finally:
            db.close()
        if not clients:
            return
        # Global monitoring: one fetch for all new exploit/PoC tools (no client name filter)
        global_repos: list = []
        try:
            global_repos = search_global_exploit_repos(max_results=200)
        except Exception as e:
            logger.warning("Global exploit fetch error: %s", e)
        # Per-client: correlate global threats to tech stack → CRITICAL alert on match
        for c in clients:
            scope = c.to_scope_dict()
            tech_stack = list(scope.get("tech_stack") or [])
            try:
                matches = filter_matching_exploits(global_repos, tech_stack) if global_repos else []
                domains = [d for d in (scope.get("domains") or []) if d and not str(d).startswith("*")]
                first_url = None
                if domains:
                    d = (domains[0] or "").strip()
                    first_url = d if d.startswith(("http://", "https://")) else f"https://{d}"
                for m in matches:
                    tech = m.matched_tech[0] if m.matched_tech else "unknown"
                    repo_url = m.exploit_repo.html_url or ("https://github.com/" + m.exploit_repo.full_name)
                    if first_url:
                        run_safe_probe(first_url, tech)
                    alerts.send_exploit_alert_if_new(c.name, tech, repo_url)
                # Client-scoped search (extra coverage)
                if tech_stack:
                    repos = fetch_exploit_repos_for_tech_stack(tech_stack)
                    client_matches = filter_matching_exploits(repos, tech_stack)
                    for m in client_matches:
                        tech = m.matched_tech[0] if m.matched_tech else "unknown"
                        repo_url = m.exploit_repo.html_url or ("https://github.com/" + m.exploit_repo.full_name)
                        alerts.send_exploit_alert_if_new(c.name, tech, repo_url)
            except Exception as e:
                logger.warning("Exploit matching error for client %s: %s", c.name, e)
    except Exception as e:
        logger.warning("exploit_matching_job error: %s", e)


def orchestrator_cycle() -> None:
    """
    One cycle: Dark Web scan (all clients) -> if match: Telegram + Fuzzer;
    then auto_check, recon+fuzz, exploit matching.
    """
    port = os.getenv("PORT", "8000")
    notify_url = f"http://127.0.0.1:{port}/internal/fuzzer-report-created"
    try:
        factory = get_session_factory()
        db = factory()
        try:
            clients = db.query(ClientModel).all()
        finally:
            db.close()
        if not clients:
            return
        clients = [c for c in clients if should_process_tenant(c.tenant_id)]
        for c in clients:
            try:
                scope = c.to_scope_dict()
                domains = [d for d in (scope.get("domains") or []) if d and not str(d).startswith("*")]
                tech_stack = list(scope.get("tech_stack") or [])
                company_names = [c.name] if c.name else []
                findings = run_darkweb_scan(domains, tech_stack, company_names)
                first_url = None
                if domains:
                    d = (domains[0] or "").strip()
                    first_url = d if d.startswith(("http://", "https://")) else f"https://{d}"
                for f in findings:
                    if alerts.send_darkweb_alert_if_new(f.target, f.source_url, f.snippet):
                        if first_url:
                            run_fuzzer_binary(first_url, notify_url=notify_url)
            except Exception as e:
                logger.warning("Dark web scan error for %s: %s", getattr(c, "name", "?"), e)
        auto_check_job()
        autonomous_recon_fuzz_job()
        exploit_matching_job()
    except Exception as e:
        logger.warning("orchestrator_cycle error: %s", e)


def autonomous_intel_harvester_job() -> int:
    """
    Real-time intelligence harvester: ingest new payloads from GitHub, Dark Web, exploit feeds.
    Dedup by hash, auto-classify expected_signature, merge into payload_signatures.json (2KB max per payload).
    Scheduled every 15 minutes; new payloads available to fuzzer on next run without restart.
    """
    try:
        return harvest_and_merge()
    except Exception as e:
        logger.warning("autonomous_intel_harvester_job failed: %s", e)
        return 0
