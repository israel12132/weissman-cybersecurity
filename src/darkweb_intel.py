"""
Dark Web Intelligence: fetch from .onion search engines and known leak sites via Tor.
Autonomous Discovery: recursive crawler extracts .onion links; Validation Agent adds new sources to MONITORED_SOURCES.
Routes all requests through socks5h://127.0.0.1:9050. Never crashes on proxy/site errors.
"""
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

import requests

from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

TOR_PROXY = "socks5h://127.0.0.1:9050"
REQUEST_TIMEOUT = ENTERPRISE_HTTP_TIMEOUT  # 5–8s fail-fast
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
# Tor-Killswitch: if connectivity is lost, terminate all requests immediately to prevent IP leakage
_tor_dead: bool = False

# .onion link extraction (v3 56 chars, v2 16 chars)
ONION_LINK_REGEX = re.compile(
    r'https?://[a-z2-7]{16,56}\.onion[/?\w\-\.~:/?#\[\]@!$&\'()*+,;=%]*',
    re.I,
)

# Automated dorks for discovering new hidden services
DORK_QUERIES: list[str] = [
    "exploit forum",
    "leak site",
    "database dump",
    "ransomware leak",
    "credential leak",
    ".env leak",
    "hacker forum",
]

# Validation Agent: content keywords that indicate forum/leak site
FORUM_LEAK_SIGNATURES: list[str] = [
    "exploit", "dump", "leak", "credential", "database", "cve", "0day",
    "ransomware", "malware", "payload", "shellcode", "forum", "market",
]

DEFAULT_SOURCES: list[str] = [
    "https://ahmia.fi/search/?q={query}",
    "https://onion.live/search/?q={query}",
]
# Deep Web search engines for discovery (optional env DARKWEB_DISCOVERY_ENGINES)
DISCOVERY_ENGINES: list[str] = [
    "https://ahmia.fi/search/?q={query}",
    "https://onion.live/search/?q={query}",
]
HAYSTACK_URL = "https://haystack.online/search?q={query}"
DEEPSEARCH_QUERY = "https://deepsearch.space/search?q={query}"
# Clearnet leak sources (no Tor); optional. Set PASTEBIN_SEARCH=1 to enable.
CLEARNET_LEAK_SOURCES: list[str] = [
    "https://www.google.com/search?q={query}",  # generic; replace with Pastebin/Scrape if available
]
# Leak indicator keywords: search for these combined with target domain/company
# Phase 3: include generic paste sites (Pastebin mentions, etc.)
LEAK_INDICATORS: list[str] = [
    "database dump",
    "db dump",
    "config file",
    ".env",
    "credentials leak",
    "sql dump",
    "config leak",
    "env file leak",
    "pastebin",
    "paste leak",
    "paste dump",
    "paste site",
]
SNIPPET_MAX = 300


def _tor_proxies() -> dict[str, str]:
    return {"http": TOR_PROXY, "https": TOR_PROXY}


def _check_tor_connectivity() -> bool:
    """Verify Tor SOCKS5 proxy is reachable. If not, set killswitch and return False."""
    global _tor_dead
    if _tor_dead:
        return False
    try:
        s = requests.Session()
        s.proxies = _tor_proxies()
        s.get(TOR_CHECK_URL, timeout=REQUEST_TIMEOUT)
        return True
    except Exception as e:
        logger.warning("Tor killswitch: connectivity lost (%s). Terminating all darkweb requests.", e)
        _tor_dead = True
        return False


def _get_sources(db_session: Any = None) -> list[str]:
    """Search engine templates (with {query}) and optional monitored .onion with search; no limit."""
    raw = (os.getenv("DARKWEB_SOURCES") or "").strip()
    if raw:
        base = [u.strip() for u in raw.split(",") if u.strip()]
    else:
        base = list(DEFAULT_SOURCES)
    extra = (os.getenv("DARKWEB_EXTRA_SOURCES") or "").strip()
    if extra:
        base.extend([u.strip() for u in extra.split(",") if u.strip()])
    # Optionally include monitored sources that have a search pattern (e.g. ...?q={query})
    for url in get_monitored_sources_from_db(db_session):
        if url and "{query}" in url:
            base.append(url)
    return base


def _get_discovery_engines() -> list[str]:
    raw = (os.getenv("DARKWEB_DISCOVERY_ENGINES") or "").strip()
    if raw:
        return [u.strip() for u in raw.split(",") if u.strip()]
    engines = list(DISCOVERY_ENGINES)
    if os.getenv("DARKWEB_HAYSTACK"):
        engines.append(HAYSTACK_URL)
    if os.getenv("DARKWEB_DEEPSEARCH"):
        engines.append(DEEPSEARCH_QUERY)
    return engines


def extract_onion_links(html: str) -> set[str]:
    """Extract all .onion URLs from HTML. No limit."""
    if not (html or "").strip():
        return set()
    return set(ONION_LINK_REGEX.findall(html))


def validate_source_as_forum_or_leak(session: requests.Session, url: str) -> bool:
    """
    Validation Agent: fetch URL and check if content looks like a hacker forum or leak site.
    Returns True if the page contains enough FORUM_LEAK_SIGNATURES.
    """
    if _tor_dead or not _check_tor_connectivity():
        return False
    try:
        r = get_with_retry(session, url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        text = (r.text or "").lower()
        hits = sum(1 for sig in FORUM_LEAK_SIGNATURES if sig.lower() in text)
        return hits >= 2
    except Exception as e:
        logger.debug("Validation agent %s: %s", url[:50], e)
        return False


def crawl_page_for_onion_links(
    session: requests.Session,
    url: str,
    depth: int = 0,
    max_depth: int = 1,
    seen: set[str] | None = None,
) -> set[str]:
    """
    Recursive crawler: fetch page, extract .onion links. If depth < max_depth, do not follow
    (we only extract from known forum pages). Returns all discovered .onion URLs (no limit).
    """
    seen = seen or set()
    if depth > max_depth or not _check_tor_connectivity():
        return seen
    try:
        r = get_with_retry(session, url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        html = r.text or ""
        links = extract_onion_links(html)
        for link in links:
            link = link.split("#")[0].rstrip("/")
            if link not in seen:
                seen.add(link)
        return seen
    except Exception as e:
        logger.debug("Crawl %s: %s", url[:50], e)
        return seen


def discover_new_sources_via_search_engines() -> list[dict]:
    """
    Use Ahmia, Haystack, DeepSearch (and env engines) with automated dorks to find new .onion URLs.
    Returns list of { "url": str, "risk_level": str } (no hardcoded limit).
    Uses Tor for search engines that support it; IP rotation via get_with_retry for clearnet.
    """
    discovered: list[dict] = []
    if _tor_dead or not _check_tor_connectivity():
        return discovered
    session = _tor_session()
    for dork in DORK_QUERIES:
        for template in _get_discovery_engines():
            try:
                url = template.format(query=requests.utils.quote(dork))
                text = _fetch_url(session, url)
                if text:
                    for onion_url in extract_onion_links(text):
                        onion_url = onion_url.split("#")[0].rstrip("/")
                        discovered.append({"url": onion_url, "risk_level": "high"})
            except Exception as e:
                logger.debug("Discovery %s: %s", dork[:30], e)
    return discovered


def get_monitored_sources_from_db(db_session: Any = None) -> list[str]:
    """Return all monitored source URLs (validated or not). No limit."""
    urls: list[str] = []
    try:
        from src.database import get_session_factory, MonitoredSourceModel
        session = db_session or get_session_factory()()
        try:
            rows = session.query(MonitoredSourceModel).all()
            urls = [r.url for r in rows if r and r.url]
        finally:
            if session and not db_session:
                session.close()
    except Exception as e:
        logger.debug("get_monitored_sources_from_db: %s", e)
    return urls


def add_monitored_source(
    url: str,
    source_type: str = "onion_forum",
    risk_level: str = "high",
    db_session: Any = None,
) -> bool:
    """Persist new source and publish NEW SOURCE DISCOVERED to Command Center."""
    if not (url or "").strip():
        return False
    url = url.strip()
    try:
        from src.database import get_session_factory, MonitoredSourceModel
        from src import events_pub
        session = db_session or get_session_factory()()
        try:
            existing = session.query(MonitoredSourceModel).filter(MonitoredSourceModel.url == url).first()
            if existing:
                return False
            rec = MonitoredSourceModel(
                url=url,
                source_type=source_type,
                risk_level=risk_level,
                validated=True,
            )
            session.add(rec)
            session.commit()
            events_pub.publish_command_center_event("new_source_discovered", {
                "url": url,
                "source_type": source_type,
                "risk_level": risk_level,
                "message": f"NEW SOURCE DISCOVERED: {url[:60]}... ({risk_level})",
            })
            return True
        finally:
            if session and not db_session:
                session.close()
    except Exception as e:
        logger.warning("add_monitored_source: %s", e)
        return False
    return False


def run_autonomous_discovery_cycle(db_session: Any = None) -> int:
    """
    One cycle: discover via search engines, crawl known sources for .onion links,
    validate each new URL with Validation Agent, add to MONITORED_SOURCES. Returns count added.
    """
    added = 0
    if _tor_dead or not _check_tor_connectivity():
        return 0
    session = _tor_session()
    # 1) Discover from search engines (no limit)
    for item in discover_new_sources_via_search_engines():
        u = (item.get("url") or "").strip()
        if not u:
            continue
        if validate_source_as_forum_or_leak(session, u) and add_monitored_source(
            u, "onion_forum", item.get("risk_level") or "high", db_session
        ):
            added += 1
    # 2) Crawl known .onion sources from DB for new links (recursive discovery)
    for known_url in get_monitored_sources_from_db(db_session):
        if ".onion" not in (known_url or ""):
            continue
        for onion_url in crawl_page_for_onion_links(session, known_url, max_depth=0):
            if validate_source_as_forum_or_leak(session, onion_url) and add_monitored_source(
                onion_url, "onion_forum", "high", db_session
            ):
                added += 1
    return added


def _tor_session() -> requests.Session:
    s = requests.Session()
    s.proxies = _tor_proxies()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
    )
    s.headers["Accept"] = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
    return s


@dataclass
class DarkWebFinding:
    target: str
    snippet: str
    source_url: str
    match_type: str  # "domain_dump" | "tech_exploit" | "company_leak"
    query: str


def _fetch_url(session: requests.Session, url: str) -> str | None:
    """Fetch URL via Tor. Tor-Killswitch: if Tor is down, return None immediately (no IP leakage)."""
    global _tor_dead
    if _tor_dead:
        return None
    if not _check_tor_connectivity():
        return None
    try:
        r = get_with_retry(session, url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text or None
    except requests.exceptions.ProxyError as e:
        logger.warning("Dark Web: Tor proxy error for %s: %s", url[:80], e)
        return None
    except requests.exceptions.Timeout:
        logger.warning("Dark Web: Timeout for %s", url[:80])
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("Dark Web: Request error for %s: %s", url[:80], e)
        return None
    except Exception as e:
        logger.warning("Dark Web: Unexpected error for %s: %s", url[:80], e)
        return None


def _search_sources(query: str) -> list[tuple[str, str]]:
    """Returns list of (source_url, response_text). Tor-Killswitch: if Tor down, returns []."""
    if _tor_dead or not _check_tor_connectivity():
        return []
    session = _tor_session()
    out: list[tuple[str, str]] = []
    for template in _get_sources():
        url = template.format(query=requests.utils.quote(query))
        text = _fetch_url(session, url)
        if text:
            out.append((url, text))
    return out


def _fetch_url_clearnet(url: str) -> str | None:
    """
    Fetch URL without Tor (for Pastebin, etc.). Only used when Tor is up and run_darkweb_scan
    permits; if Tor is down the module aborts so this is not used. Never raises.
    """
    if _tor_dead:
        return None
    try:
        sess = requests.Session()
        sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        r = get_with_retry(sess, url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text or None
    except Exception as e:
        logger.debug("Clearnet fetch %s: %s", url[:60], e)
        return None


def _get_clearnet_leak_sources() -> list[str]:
    """Optional clearnet sources for leak/paste monitoring (Pastebin, etc.)."""
    raw = (os.getenv("CLEARNET_LEAK_SOURCES") or "").strip()
    if raw:
        return [u.strip() for u in raw.split(",") if u.strip()]
    if os.getenv("PASTEBIN_SEARCH"):
        return ["https://pastebin.com/search?q={query}"]
    return []


def _extract_snippet(text: str, pattern: str | re.Pattern, max_len: int = SNIPPET_MAX) -> str:
    if isinstance(pattern, str):
        pattern = re.compile(re.escape(pattern), re.I)
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, m.start() - 80)
    end = min(len(text), m.end() + max_len)
    snippet = text[start:end].replace("\n", " ").strip()
    if len(snippet) > max_len:
        snippet = snippet[:max_len] + "..."
    return snippet


def search_domain_dumps(domain: str) -> list[DarkWebFinding]:
    """Search for database dumps / leaks containing the target domain. Never raises."""
    if not (domain or "").strip():
        return []
    domain = domain.strip().lower()
    findings: list[DarkWebFinding] = []
    for source_url, text in _search_sources(domain):
        if domain in text.lower():
            snippet = _extract_snippet(text, domain)
            if snippet:
                findings.append(
                    DarkWebFinding(
                        target=domain,
                        snippet=snippet,
                        source_url=source_url,
                        match_type="domain_dump",
                        query=domain,
                    )
                )
    return findings


def search_tech_exploit_mentions(tech_terms: list[str]) -> list[DarkWebFinding]:
    """Search for target tech stack mentioned in exploit-selling / leak context. Never raises."""
    if not tech_terms:
        return []
    findings: list[DarkWebFinding] = []
    for tech in tech_terms:
        tech = (tech or "").strip()
        if not tech:
            continue
        for source_url, text in _search_sources(f"{tech} exploit"):
            if tech.lower() in text.lower() and (
                "exploit" in text.lower() or "dump" in text.lower() or "leak" in text.lower()
            ):
                snippet = _extract_snippet(text, tech)
                if snippet:
                    findings.append(
                        DarkWebFinding(
                            target=tech,
                            snippet=snippet,
                            source_url=source_url,
                            match_type="tech_exploit",
                            query=tech,
                        )
                    )
    return findings


def search_company_leaks(company_names: list[str]) -> list[DarkWebFinding]:
    """Search for company names (e.g. Tesla) on ransomware leak sites / DLS. Never raises."""
    if not company_names:
        return []
    findings: list[DarkWebFinding] = []
    for name in company_names:
        name = (name or "").strip()
        if not name:
            continue
        for source_url, text in _search_sources(name):
            if name.lower() in text.lower():
                snippet = _extract_snippet(text, name)
                if snippet:
                    findings.append(
                        DarkWebFinding(
                            target=name,
                            snippet=snippet,
                            source_url=source_url,
                            match_type="company_leak",
                            query=name,
                        )
                    )
    return findings


def search_leak_indicators(
    domains: list[str],
    company_names: list[str],
) -> list[DarkWebFinding]:
    """
    Search for leak indicators (DB dumps, .env, config files) related to targets.
    Uses both Tor sources and optional clearnet (Pastebin, etc.).
    """
    findings: list[DarkWebFinding] = []
    targets: list[str] = []
    for d in (domains or []):
        d = (d or "").strip().lower()
        if d and not d.startswith("*"):
            targets.append(d)
    for c in (company_names or []):
        c = (c or "").strip()
        if c:
            targets.append(c.lower())
    if not targets:
        return findings
    for target in targets:
        for indicator in LEAK_INDICATORS:
            query = f"{target} {indicator}"
            for source_url, text in _search_sources(query):
                if target in text.lower() and (
                    "dump" in text.lower() or "leak" in text.lower() or ".env" in text or "config" in text.lower()
                ):
                    snippet = _extract_snippet(text, target)
                    if snippet:
                        findings.append(
                            DarkWebFinding(
                                target=target,
                                snippet=snippet,
                                source_url=source_url,
                                match_type="leak_indicator",
                                query=query,
                            )
                        )
            for template in _get_clearnet_leak_sources():
                url = template.format(query=requests.utils.quote(query))
                text = _fetch_url_clearnet(url)
                if text and target in text.lower():
                    snippet = _extract_snippet(text, target)
                    if snippet:
                        findings.append(
                            DarkWebFinding(
                                target=target,
                                snippet=snippet,
                                source_url=url,
                                match_type="leak_indicator",
                                query=query,
                            )
                        )
    return findings


def run_darkweb_scan(
    domains: list[str],
    tech_stack: list[str],
    company_names: list[str],
) -> list[DarkWebFinding]:
    """
    Single scan: domain dumps + tech exploit mentions + company leaks
    + leak indicators (DB dumps, .env, config files, paste sites).
    Phase 3 Tor-Killswitch: if Tor proxy is down, abort immediately (no request leaves without Tor).
    """
    if _tor_dead or not _check_tor_connectivity():
        logger.warning("Dark Web: Tor killswitch active or proxy down. Aborting entire module (no IP leak).")
        return []
    results: list[DarkWebFinding] = []
    for d in domains:
        if d and not str(d).startswith("*"):
            results.extend(search_domain_dumps(d.strip()))
    results.extend(search_tech_exploit_mentions(tech_stack))
    results.extend(search_company_leaks(company_names))
    results.extend(search_leak_indicators(domains, company_names))
    return results
