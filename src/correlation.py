"""Correlate intelligence findings with each client's authorized scope.
Phase 1: Short-lived cache (5–10 min) for feed results to avoid rate limits (NVD, GitHub, OSV, OTX).
Cache key MUST include query/technology so Client B does not get Client A's cached result.
"""
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

from src.config import load_config
from src.models import ClientFinding, Finding, FindingType, normalize_tech_stack_to_list
from src.feeds import NVDFeed, GitHubFeed, OSVFeed, OTXFeed, HIBPFeed
from src.feeds.base import FeedResult
from src.fingerprint import fingerprint_ip_ranges, fingerprint_urls, merge_fingerprint_into_scope

FEED_CACHE_TTL_SECONDS = int(os.getenv("WEISSMAN_FEED_CACHE_TTL", "300"))  # 5 min default
FEED_CACHE_PREFIX = "weissman:feed:"


def _cache_key_suffix_for_clients(db_clients: list[dict]) -> str:
    """Generate a short hash of tech_stack per client so cache keys differ by technology/query."""
    tech_context = []
    for row in db_clients or []:
        scope = row.get("scope") or {}
        if isinstance(scope, str):
            try:
                scope = json.loads(scope)
            except Exception:
                scope = {}
        tech = tuple(sorted((scope.get("tech_stack") or [])))
        tech_context.append(tech)
    blob = json.dumps(tech_context, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _cached_feed(
    feed_name: str,
    fetch_fn: Callable[[], FeedResult],
    cache_key_suffix: str | None = None,
) -> FeedResult:
    """Return feed result from Redis cache if present and not expired, else fetch and cache.
    cache_key_suffix MUST be set when correlating so cache differentiates by technology/query.
    """
    suffix = (cache_key_suffix or "global").strip() or "global"
    key = f"{FEED_CACHE_PREFIX}{feed_name}:{suffix}"
    try:
        import redis
        r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        raw = r.get(key)
        if raw is not None:
            data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
            findings = [Finding.model_validate(f) for f in data.get("findings", [])]
            return FeedResult(
                findings=findings,
                source=data.get("source", feed_name),
                error=data.get("error"),
            )
    except Exception:
        pass
    result = fetch_fn()
    try:
        import redis
        r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        payload = {
            "source": result.source,
            "error": result.error,
            "findings": [f.model_dump(mode="json") for f in result.findings],
        }
        r.setex(key, FEED_CACHE_TTL_SECONDS, json.dumps(payload, default=str))
    except Exception:
        pass
    return result


def _intel_config_from_env() -> dict[str, Any]:
    return {
        "nvd_api_key": os.getenv("NVD_API_KEY", ""),
        "github_token": os.getenv("GITHUB_TOKEN", ""),
        "otx_api_key": os.getenv("OTX_API_KEY", ""),
        "hibp_api_key": os.getenv("HIBP_API_KEY", ""),
    }


def get_all_feed_results(config):
    """Fetch from all enabled intelligence feeds."""
    results = []
    if config.intelligence.nvd.enabled:
        results.append(NVDFeed(api_key=config.intelligence.nvd.api_key).fetch())
    if config.intelligence.github.enabled:
        results.append(GitHubFeed(token=config.intelligence.github.token).fetch())
    if config.intelligence.osv.enabled:
        results.append(OSVFeed().fetch())
    if config.intelligence.otx.enabled and config.intelligence.otx.api_key:
        results.append(OTXFeed(api_key=config.intelligence.otx.api_key).fetch())
    # HIBP is used per-client per-domain below
    return results


def correlate_findings_to_clients(config_path: str = "config.yaml") -> list[ClientFinding]:
    """Run all feeds and correlate findings to each client's scope. Only in-scope results."""
    config = load_config(config_path)
    client_findings: list[ClientFinding] = []

    feed_results = get_all_feed_results(config)
    hibp = HIBPFeed(api_key=config.intelligence.hibp.api_key) if config.intelligence.hibp.enabled else None

    for client in config.clients:
        tech_stack = [t.lower() for t in client.scope.tech_stack]
        domains = [d.strip().lower() for d in client.scope.domains if d and not d.startswith("*")]

        for result in feed_results:
            if result.error:
                continue
            for finding in result.findings:
                if finding.matches_tech_stack(client.scope.tech_stack):
                    client_findings.append(
                        ClientFinding(
                            client_id=client.id,
                            finding=finding,
                            relevance_note=f"Matches tech stack: {finding.affected_components}",
                        )
                    )

        # HIBP: only for domains in client scope (authorized)
        if hibp and domains:
            for domain in domains[:10]:  # limit to avoid rate limit
                for finding in hibp.check_breaches_for_domain(domain):
                    client_findings.append(
                        ClientFinding(
                            client_id=client.id,
                            finding=finding,
                            relevance_note=f"Domain {domain} found in breach data",
                        )
                    )

    return client_findings


def correlate_findings_from_db(
    db_clients: list[dict],
    intel_config: dict[str, str] | None = None,
) -> list[ClientFinding]:
    """Run feeds and correlate to clients from DB. db_clients: list of {id, name, domains, ip_ranges, tech_stack, contact_email}."""
    intel = intel_config or _intel_config_from_env()
    client_findings: list[ClientFinding] = []
    cache_suffix = _cache_key_suffix_for_clients(db_clients)

    results = []
    results.append(_cached_feed("nvd", lambda: NVDFeed(api_key=intel.get("nvd_api_key", "")).fetch(), cache_suffix))
    results.append(_cached_feed("github", lambda: GitHubFeed(token=intel.get("github_token", "")).fetch(), cache_suffix))
    results.append(_cached_feed("osv", lambda: OSVFeed().fetch(), cache_suffix))
    if intel.get("otx_api_key"):
        results.append(_cached_feed("otx", lambda: OTXFeed(api_key=intel["otx_api_key"]).fetch(), cache_suffix))
    hibp = HIBPFeed(api_key=intel.get("hibp_api_key", "")) if intel.get("hibp_api_key") else None

    for row in db_clients:
        cid = str(row.get("id", ""))
        scope = row.get("scope", {})
        if isinstance(scope, str):
            scope = json.loads(scope) if scope else {}
        domains = [d.strip().lower() for d in scope.get("domains", []) if d and not str(d).startswith("*")]
        raw_tech = scope.get("tech_stack")
        tech_stack = normalize_tech_stack_to_list(raw_tech if isinstance(raw_tech, list) else (raw_tech or ""))

        # Active fingerprinting: scan target URLs and merge discovered tech into tech_stack
        if domains:
            urls = []
            for d in domains[:15]:
                d = d.strip()
                if not d or d.startswith("*"):
                    continue
                if d.startswith("http://") or d.startswith("https://"):
                    urls.append(d)
                else:
                    urls.append(f"https://{d}")
            if urls:
                fp = fingerprint_urls(urls)
                tech_stack = merge_fingerprint_into_scope({"tech_stack": tech_stack, "domains": domains}, fp)
                tech_stack = normalize_tech_stack_to_list(tech_stack)
                if not tech_stack and scope.get("tech_stack"):
                    tech_stack = normalize_tech_stack_to_list(scope.get("tech_stack"))

        # Active fingerprinting on IP ranges (ports 80, 443, 8080) and merge tech
        ip_ranges = [r.strip() for r in scope.get("ip_ranges") or [] if r and str(r).strip()]
        if ip_ranges:
            fp_ip = fingerprint_ip_ranges(ip_ranges[:5])
            if fp_ip:
                tech_stack = merge_fingerprint_into_scope(
                    {"tech_stack": tech_stack, "domains": domains},
                    fp_ip,
                )
                tech_stack = normalize_tech_stack_to_list(tech_stack)
            if not tech_stack and scope.get("tech_stack"):
                tech_stack = normalize_tech_stack_to_list(scope.get("tech_stack"))

        for result in results:
            if result.error:
                continue
            for finding in result.findings:
                if not finding.matches_tech_stack(tech_stack):
                    continue
                matched = finding.matched_tech_stack(tech_stack)
                if matched:
                    relevance_note = f"Matches tech stack: {matched}"
                else:
                    displayed = [c for c in finding.affected_components if c and str(c).lower() != "unknown"]
                    relevance_note = f"Matches tech stack: {displayed}" if displayed else "Matches scope"
                client_findings.append(
                    ClientFinding(
                        client_id=cid,
                        finding=finding,
                        relevance_note=relevance_note,
                    )
                )

        if hibp and domains:
            for domain in domains[:10]:
                for finding in hibp.check_breaches_for_domain(domain):
                    client_findings.append(
                        ClientFinding(
                            client_id=cid,
                            finding=finding,
                            relevance_note=f"Domain {domain} found in breach data",
                        )
                    )

    return client_findings


def dedupe_by_finding_id(client_findings: list[ClientFinding]) -> list[ClientFinding]:
    """One finding per (client_id, finding.id)."""
    seen = set()
    out = []
    for cf in client_findings:
        key = (cf.client_id, cf.finding.id)
        if key in seen:
            continue
        seen.add(key)
        out.append(cf)
    return out
