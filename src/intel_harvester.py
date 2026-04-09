"""
Real-Time Intelligence Harvester: ingest new attack vectors from GitHub, Dark Web, and
exploit DB feeds every 15 minutes. Dedupe by payload hash, auto-classify expected_signature,
merge into payload_signatures.json. Max payload size 2KB (sanity gate).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from urllib.parse import quote

from src.http_client import get_with_retry, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 2048  # 2KB sanity gate per payload
MAX_TOTAL_RULES = 10_000  # cap total rules so JSON and Rust memory stay bounded
PAYLOAD_SIGNATURES_FILENAME = "payload_signatures.json"

# GitHub high-priority: raw file URLs and search queries
GITHUB_RAW_BASES = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix-2.txt",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/README.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
]
GITHUB_SEARCH_QUERIES = ["new cve poc", "fuzzing payloads", "bypass waf", "sqli payload", "xss payload"]
GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_PER_PAGE = 20

# Exploit DB / Packet Storm / CXSecurity RSS
EXPLOIT_FEEDS = [
    "https://www.exploit-db.com/rss.xml",
    "https://rss.packetstormsecurity.com/",
    "https://cxsecurity.com/wlb/rss/vulnerabilities",
]
FEED_TIMEOUT = 10
DARKWEB_FETCH_TIMEOUT = 10  # strict timeout for Tor so one slow onion doesn't hang the worker

# Auto-classification: payload substring -> expected_signature (regex)
CLASSIFICATION_MAP = [
    (lambda p: "<script>" in p or "alert(" in p or "onerror=" in p.lower(), "alert\\(|onerror|<script|script>|syntaxerror"),
    (lambda p: re.search(r"\b(SELECT|UNION|OR\s+1\s*=\s*1|'|\")\s*(OR|AND)", p, re.I) is not None or "mysql_fetch" in p.lower(), "syntax error|mysql_fetch|SQL syntax|Warning.*mysql|mysqli|ORA-|pg_"),
    (lambda p: "../" in p or "..\\\\" in p or "etc/passwd" in p.lower() or "passwd" in p, "root:x:|root:\\*:0:0|root::0:0:"),
    (lambda p: "{{" in p and "}}" in p or "${" in p, "49|7\\*7|template|expression|eval"),
    (lambda p: "jndi:" in p.lower() or "ldap://" in p.lower(), "jndi|ldap|log4j|rce"),
]
DEFAULT_SIGNATURE = "error|exception|warning|invalid|syntax"


def _payload_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def _sanitize_payload(s: str) -> str | None:
    s = (s or "").strip()
    if not s or len(s.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return None
    if s.startswith("#") or s.startswith("//") or len(s) < 3:
        return None
    return s


def _auto_classify(payload: str) -> str:
    for pred, sig in CLASSIFICATION_MAP:
        if pred(payload):
            return sig
    return DEFAULT_SIGNATURE


def _extract_payloads_from_text(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            line = line.split("\t")[0].strip()
        if " " in line and not line.startswith(("'", '"', "<", "{", "$", "%")):
            for part in line.split():
                if 3 <= len(part) <= 500:
                    out.append(part)
        else:
            if 3 <= len(line) <= 500:
                out.append(line)
    return out


def _extract_from_markdown(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"`([^`]{3,500})`", text):
        out.append(m.group(1))
    for m in re.finditer(r"```\w*\n(.*?)```", text, re.S):
        for line in m.group(1).splitlines():
            line = line.strip()
            if 3 <= len(line) <= 500 and not line.startswith("#"):
                out.append(line)
    return out


def fetch_github_raw(url: str, token: str | None) -> list[str]:
    payloads: list[str] = []
    try:
        s = requests_session()
        s.headers["Accept"] = "application/vnd.github.raw"
        if token:
            s.headers["Authorization"] = f"Bearer {token}"
        r = get_with_retry(s, url, timeout=ENTERPRISE_HTTP_TIMEOUT)
        if r.status_code != 200:
            return []
        text = (r.text or "")[:2 * 1024 * 1024]  # sanity: max 2MB per response
        for raw in (_extract_payloads_from_text(text) + _extract_from_markdown(text))[:500]:
            p = _sanitize_payload(raw)
            if p:
                payloads.append(p)
        time.sleep(0.5)
    except Exception as e:
        logger.debug("Harvester GitHub raw %s: %s", url[:60], e)
    return payloads


def requests_session():
    import requests
    return requests.Session()


def fetch_github_search(query: str, token: str | None) -> list[str]:
    payloads_list: list[str] = []
    if not token:
        return payloads_list
    try:
        s = requests_session()
        s.headers["Accept"] = "application/vnd.github.v3+json"
        s.headers["Authorization"] = f"Bearer {token}"
        r = get_with_retry(s, GITHUB_SEARCH_URL, params={"q": query, "per_page": GITHUB_PER_PAGE}, timeout=ENTERPRISE_HTTP_TIMEOUT)
        if r.status_code != 200:
            return payloads_list
        data = r.json()
        for item in data.get("items", [])[:10]:
            repo = item.get("repository", {})
            full = repo.get("full_name", "")
            path = item.get("path", "")
            if not full or not path:
                continue
            raw_url = f"https://raw.githubusercontent.com/{full}/master/{path}"
            raw_url = raw_url.replace("/master/", "/main/") if "master" in raw_url else raw_url
            try:
                r2 = s.get(raw_url, timeout=ENTERPRISE_HTTP_TIMEOUT)
                if r2.status_code == 200:
                    for raw in _extract_payloads_from_text(r2.text or "") + _extract_from_markdown(r2.text or ""):
                        p = _sanitize_payload(raw)
                        if p:
                            payloads_list.append(p)
                time.sleep(0.3)
            except Exception:
                pass
        time.sleep(1)
    except Exception as e:
        logger.debug("Harvester GitHub search %s: %s", query, e)
    return payloads_list


def fetch_exploit_feeds() -> list[str]:
    payloads: list[str] = []
    import xml.etree.ElementTree as ET
    for feed_url in EXPLOIT_FEEDS:
        try:
            s = requests_session()
            r = s.get(feed_url, timeout=FEED_TIMEOUT)
            if r.status_code != 200:
                continue
            root = ET.fromstring(r.content)
            for item in root.iter():
                if item.tag.endswith("item"):
                    title = None
                    desc = None
                    for c in item:
                        if c.tag.endswith("title"):
                            title = (c.text or "").strip()
                        if c.tag.endswith("description"):
                            desc = (c.text or "").strip()
                    for raw in _extract_payloads_from_text((title or "") + " " + (desc or "")):
                        p = _sanitize_payload(raw)
                        if p:
                            payloads.append(p)
            time.sleep(0.5)
        except Exception as e:
            logger.debug("Harvester feed %s: %s", feed_url[:50], e)
    return payloads


def fetch_darkweb_paste_snippets() -> list[str]:
    """Fetch from Tor-routed sources with strict timeout=10s; catch Timeout so harvester continues."""
    payloads: list[str] = []
    try:
        import requests
        from src.darkweb_intel import _tor_session, _check_tor_connectivity, _tor_dead
        if _tor_dead or not _check_tor_connectivity():
            return payloads
        session = _tor_session()
        session.timeout = DARKWEB_FETCH_TIMEOUT
        for dork in ["exploit payload", "sqli dork", "xss bypass"]:
            try:
                from src.darkweb_intel import _get_sources
                for template in _get_sources()[:2]:
                    url = template.format(query=quote(dork))
                    try:
                        r = session.get(url, timeout=DARKWEB_FETCH_TIMEOUT)
                        if r.status_code == 200 and r.text:
                            for raw in _extract_payloads_from_text(r.text)[:30]:
                                p = _sanitize_payload(raw)
                                if p:
                                    payloads.append(p)
                    except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout, requests.exceptions.Timeout):
                        continue
                    except Exception:
                        pass
                    time.sleep(0.5)
            except Exception:
                pass
    except ImportError:
        pass
    return payloads


def get_payload_signatures_path() -> Path:
    base = Path(__file__).resolve().parent.parent / "fingerprint_engine" / "config"
    env_path = os.getenv("WEISSMAN_PAYLOAD_SIGNATURES")
    if env_path:
        return Path(env_path)
    return base / PAYLOAD_SIGNATURES_FILENAME


def load_existing_rules(path: Path) -> tuple[list[dict], set[str]]:
    seen_hashes = set()
    rules = []
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for r in data if isinstance(data, list) else []:
                if isinstance(r, dict) and r.get("payload"):
                    rules.append({"payload": r["payload"], "expected_signature": r.get("expected_signature", DEFAULT_SIGNATURE)})
                    seen_hashes.add(_payload_hash(r["payload"]))
        except Exception as e:
            logger.warning("Harvester load existing %s: %s", path, e)
    return rules, seen_hashes


def harvest_and_merge() -> int:
    token = (os.getenv("GITHUB_TOKEN") or "").strip() or None
    all_payloads: list[str] = []

    for url in GITHUB_RAW_BASES:
        all_payloads.extend(fetch_github_raw(url, token))
        time.sleep(0.5)

    for q in GITHUB_SEARCH_QUERIES[:3]:
        all_payloads.extend(fetch_github_search(q, token))
        time.sleep(1)

    all_payloads.extend(fetch_exploit_feeds())
    all_payloads.extend(fetch_darkweb_paste_snippets())

    # Dedup by hash before classification to save CPU
    seen_cycle: set[str] = set()
    unique_payloads: list[str] = []
    for p in all_payloads:
        h = _payload_hash(p)
        if h in seen_cycle:
            continue
        seen_cycle.add(h)
        unique_payloads.append(p)

    path = get_payload_signatures_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    rules, seen = load_existing_rules(path)
    added = 0
    for payload in unique_payloads:
        h = _payload_hash(payload)
        if h in seen:
            continue
        seen.add(h)
        expected_sig = _auto_classify(payload)
        rules.append({"payload": payload[:2048], "expected_signature": expected_sig})
        added += 1

    if rules:
        if len(rules) > MAX_TOTAL_RULES:
            rules = rules[:MAX_TOTAL_RULES]
            logger.info("Intel harvester: capped to %d rules", MAX_TOTAL_RULES)
        try:
            path.write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("Intel harvester: merged %d new payloads into %s (total %d)", added, path, len(rules))
        except Exception as e:
            logger.warning("Intel harvester write %s: %s", path, e)
    return added
