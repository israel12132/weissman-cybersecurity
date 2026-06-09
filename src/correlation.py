"""Correlate intelligence findings with each client's authorized scope.
Phase 1: Short-lived cache (5–10 min) for feed results to avoid rate limits (NVD, GitHub, OSV, OTX).
Cache key MUST include query/technology so Client B does not get Client A's cached result.
"""
import asyncio
import hashlib
import json
import logging
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

from src.config import load_config
from src.feed_cache import get_cached_feed, set_cached_feed
from src.models import ClientFinding, Finding, normalize_tech_stack_to_list
from src.feeds import NVDFeed, GitHubFeed, OSVFeed, OTXFeed, HIBPFeed
from src.feeds.base import FeedResult
from src.fingerprint import fingerprint_ip_ranges, fingerprint_urls, merge_fingerprint_into_scope

logger = logging.getLogger("weissman.correlation")

# Bound per-key lock bookkeeping to prevent unbounded growth for highly dynamic keys.
_MAX_FEED_FILL_LOCKS = 512
_feed_fill_locks: OrderedDict[str, threading.Lock] = OrderedDict()
_feed_fill_locks_guard = threading.Lock()


def _get_feed_fill_lock(cache_key: str) -> threading.Lock:
    with _feed_fill_locks_guard:
        lock = _feed_fill_locks.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            _feed_fill_locks[cache_key] = lock
        else:
            _feed_fill_locks.move_to_end(cache_key)
        while len(_feed_fill_locks) > _MAX_FEED_FILL_LOCKS:
            current_lock_count = len(_feed_fill_locks)
            max_attempts = min(current_lock_count, 8)
            evicted = False
            checked_keys = list(_feed_fill_locks.keys())[:max_attempts]
            for oldest_key in checked_keys:
                if oldest_key not in _feed_fill_locks:
                    continue
                oldest_lock = _feed_fill_locks[oldest_key]
                if oldest_lock.locked():
                    _feed_fill_locks.move_to_end(oldest_key)
                    continue
                _feed_fill_locks.pop(oldest_key, None)
                evicted = True
                break
            if not evicted:
                break
        return lock


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
    """Return cached feed results or fetch and cache with per-key anti-stampede locking."""
    suffix = (cache_key_suffix or "global").strip() or "global"
    cache_key = f"{feed_name}:{suffix}"

    def _to_findings(payloads: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for item in payloads:
            try:
                out.append(Finding.model_validate(item))
            except Exception as exc:
                logger.debug("Skipping invalid cached finding payload: %s", exc)
                continue
        return out

    cached = get_cached_feed(cache_key)
    if cached is not None:
        return FeedResult(findings=_to_findings(cached), source=feed_name)

    lock = _get_feed_fill_lock(cache_key)
    with lock:
        cached = get_cached_feed(cache_key)
        if cached is not None:
            return FeedResult(findings=_to_findings(cached), source=feed_name)

        result = fetch_fn()
        if not result.error:
            set_cached_feed(cache_key, result.findings, cache_empty=True)
        return result


def _intel_config_from_env() -> dict[str, Any]:
    return {
        "nvd_api_key": os.getenv("NVD_API_KEY", ""),
        "github_token": os.getenv("GITHUB_TOKEN", ""),
        "otx_api_key": os.getenv("OTX_API_KEY", ""),
        "hibp_api_key": os.getenv("HIBP_API_KEY", ""),
    }


def get_all_feed_results(config, cache_suffix: str | None = None):
    """
    Fetch from all enabled intelligence feeds with caching.

    Parameters
    ----------
    config : Configuration object
        Contains intelligence feed settings
    cache_suffix : str or None
        Optional cache key suffix for client-specific caching

    Returns
    -------
    list[FeedResult]
        Results from all enabled feeds
    """
    results = []

    if config.intelligence.nvd.enabled:
        nvd_feed = NVDFeed(api_key=config.intelligence.nvd.api_key)
        result = _cached_feed(
            "nvd",
            lambda: nvd_feed.fetch(),
            cache_key_suffix=cache_suffix,
        )
        results.append(result)

    if config.intelligence.github.enabled:
        github_feed = GitHubFeed(token=config.intelligence.github.token)
        result = _cached_feed(
            "github",
            lambda: github_feed.fetch(),
            cache_key_suffix=cache_suffix,
        )
        results.append(result)

    if config.intelligence.osv.enabled:
        osv_feed = OSVFeed()
        result = _cached_feed(
            "osv",
            lambda: osv_feed.fetch(),
            cache_key_suffix=cache_suffix,
        )
        results.append(result)

    if config.intelligence.otx.enabled and config.intelligence.otx.api_key:
        otx_feed = OTXFeed(api_key=config.intelligence.otx.api_key)
        result = _cached_feed(
            "otx",
            lambda: otx_feed.fetch(),
            cache_key_suffix=cache_suffix,
        )
        results.append(result)

    # HIBP is used per-client per-domain below
    return results


async def get_all_feed_results_async(config, cache_suffix: str | None = None):
    """
    Fetch from all enabled intelligence feeds asynchronously with caching.

    This version uses asyncio.gather() to fetch from multiple feeds in parallel,
    significantly improving performance when multiple feeds are enabled.

    Parameters
    ----------
    config : Configuration object
        Contains intelligence feed settings
    cache_suffix : str or None
        Optional cache key suffix for client-specific caching

    Returns
    -------
    list[FeedResult]
        Results from all enabled feeds
    """
    import concurrent.futures

    # Prepare all feed tasks
    tasks = []

    if config.intelligence.nvd.enabled:
        nvd_feed = NVDFeed(api_key=config.intelligence.nvd.api_key)
        tasks.append(("nvd", lambda: nvd_feed.fetch()))

    if config.intelligence.github.enabled:
        github_feed = GitHubFeed(token=config.intelligence.github.token)
        tasks.append(("github", lambda: github_feed.fetch()))

    if config.intelligence.osv.enabled:
        osv_feed = OSVFeed()
        tasks.append(("osv", lambda: osv_feed.fetch()))

    if config.intelligence.otx.enabled and config.intelligence.otx.api_key:
        otx_feed = OTXFeed(api_key=config.intelligence.otx.api_key)
        tasks.append(("otx", lambda: otx_feed.fetch()))

    # Run all feed fetches concurrently
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = [
            loop.run_in_executor(
                executor,
                lambda name=name, fn=fn: _cached_feed(name, fn, cache_suffix),
            )
            for name, fn in tasks
        ]
        results = await asyncio.gather(*futures, return_exceptions=True)

    # Filter out exceptions and return valid results
    valid_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            feed_name = tasks[i][0]
            logger.warning("Feed %s failed: %s", feed_name, result)
        else:
            valid_results.append(result)

    return valid_results


def correlate_findings_to_clients(config_path: str = "config.yaml") -> list[ClientFinding]:
    """Run all feeds and correlate findings to each client's scope. Only in-scope results."""
    config = load_config(config_path)
    client_findings: list[ClientFinding] = []

    feed_results = get_all_feed_results(config)
    hibp = HIBPFeed(api_key=config.intelligence.hibp.api_key) if config.intelligence.hibp.enabled else None

    for client in config.clients:
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
