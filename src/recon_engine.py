"""
Weissman-cybersecurity: Attack Surface Discovery & Shadow IT Hunter.
Enterprise: streaming/paginated recon — no hard caps; batch processing for massive asset lists.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.http_client import safe_get, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# Enterprise: unlimited scale; batch size for memory safety (0 = no batching / full iteration)
def _recon_batch_size() -> int:
    return max(1, int(os.getenv("RECON_BATCH_SIZE", "500")))

def _recon_max_subdomains() -> int | None:
    v = os.getenv("RECON_MAX_SUBDOMAINS", "0").strip()
    if v in ("0", "", "none", "unlimited"):
        return None
    return max(0, int(v))

def _recon_max_bucket_candidates() -> int | None:
    v = os.getenv("RECON_MAX_BUCKET_CANDIDATES", "0").strip()
    if v in ("0", "", "none", "unlimited"):
        return None
    return max(0, int(v))

# ---------------------------------------------------------------------------
# Asset model & mapping
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredAsset:
    """Single discovered asset (subdomain, IP, bucket)."""
    asset_type: str  # subdomain, ip, s3_bucket, azure_blob
    value: str
    source: str  # ct, dns_brute, bucket_scan
    confidence: str  # high, medium, low
    risk_impact: str  # high, medium, low
    extra: dict[str, Any] = field(default_factory=dict)


def _normalize_asset_id(asset: DiscoveredAsset) -> str:
    """Unique identifier for dedup and snapshot storage."""
    return f"{asset.asset_type}:{asset.value}".strip().lower()


def group_assets_by_confidence_and_risk(
    assets: list[DiscoveredAsset],
) -> dict[str, list[DiscoveredAsset]]:
    """
    AI-driven asset mapping: group by Confidence Level and Risk Impact.
    Returns keys: high_confidence, medium_confidence, low_confidence,
    high_risk, medium_risk, low_risk, and by_source (ct, dns_brute, bucket).
    """
    by_confidence: dict[str, list[DiscoveredAsset]] = {
        "high_confidence": [],
        "medium_confidence": [],
        "low_confidence": [],
    }
    by_risk: dict[str, list[DiscoveredAsset]] = {
        "high_risk": [],
        "medium_risk": [],
        "low_risk": [],
    }
    by_source: dict[str, list[DiscoveredAsset]] = {}

    for a in assets:
        by_confidence[f"{a.confidence}_confidence"].append(a)
        by_risk[f"{a.risk_impact}_risk"].append(a)
        by_source.setdefault(a.source, []).append(a)

    return {
        **by_confidence,
        **by_risk,
        "by_source": by_source,
        "all": assets,
    }


# ---------------------------------------------------------------------------
# Certificate Transparency
# ---------------------------------------------------------------------------

def _ct_url(domain: str) -> str:
    return f"https://crt.sh/?q=%25.{domain}&output=json"

def enumerate_subdomains_ct(domain: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> list[DiscoveredAsset]:
    """Passive subdomain discovery via Certificate Transparency logs (crt.sh)."""
    domain = (domain or "").strip().lower()
    if not domain or ".." in domain or " " in domain:
        return []
    assets: list[DiscoveredAsset] = []
    seen: set[str] = set()
    try:
        url = _ct_url(domain)
        r = safe_get(url, timeout=min(timeout, 8))
        if r.status_code != 200:
            return []
        data = r.json() if r.text else []
        if not isinstance(data, list):
            return []
        base_domain = domain.split(".")[-2] + "." + domain.split(".")[-1] if "." in domain else domain
        for entry in data:
            name = (entry.get("name_value") or entry.get("common_name") or "").strip().lower()
            for part in name.split("\n"):
                part = part.strip().lower()
                if not part or part in seen:
                    continue
                if not part.endswith("." + domain) and part != domain:
                    if not part.endswith("." + base_domain):
                        continue
                if "*." in part:
                    part = part.replace("*.", "")
                if not re.match(r"^[a-z0-9][a-z0-9.-]*$", part):
                    continue
                seen.add(part)
                assets.append(DiscoveredAsset(
                    asset_type="subdomain",
                    value=part,
                    source="ct",
                    confidence="high",
                    risk_impact="medium",
                    extra={"raw": entry},
                ))
    except Exception as e:
        logger.warning("CT enumeration failed for %s: %s", domain, e)
    return assets


# ---------------------------------------------------------------------------
# DNS brute (Python fallback; Rust used when binary available)
# ---------------------------------------------------------------------------

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta", "app",
    "portal", "secure", "vpn", "git", "jenkins", "ci", "cdn", "static", "assets",
    "blog", "shop", "store", "support", "help", "docs", "wiki", "status", "monitor",
    "mx", "smtp", "ns1", "ns2", "webmail", "email", "cloud", "aws", "azure",
    "internal", "intranet", "extranet", "demo", "sandbox", "backup", "db", "mysql",
    "redis", "elastic", "kibana", "grafana", "prometheus", "gitlab", "jira",
]


def _run_rust_dns_enum(domain: str, wordlist_path: str | None = None) -> list[str]:
    """Call Rust fingerprint_engine subdomains for fast multi-threaded DNS enumeration."""
    root = Path(__file__).resolve().parent.parent
    bin_dir = root / "fingerprint_engine" / "target" / "release"
    for subdir in ("release", "debug"):
        binary = (root / "fingerprint_engine" / "target" / subdir / "fingerprint_engine")
        if not binary.exists():
            continue
        try:
            cmd = [str(binary), "subdomains", domain]
            if wordlist_path:
                cmd.extend(["--wordlist", wordlist_path])
            out = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(root),
            )
            if out.returncode == 0 and out.stdout and out.stdout.strip():
                raw = out.stdout.strip()
                if raw.startswith("["):
                    data = json.loads(raw)
                    return data if isinstance(data, list) else []
        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug("Rust DNS enum not available: %s", e)
        break
    return []


def enumerate_subdomains_dns(domain: str, wordlist: list[str] | None = None) -> list[DiscoveredAsset]:
    """
    Subdomain enumeration: try Rust engine first (multi-threaded); fallback to Python.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return []
    wordlist = wordlist or COMMON_SUBDOMAINS
    # Prefer Rust for speed
    found = _run_rust_dns_enum(domain)
    if not found:
        # Python fallback: resolve via system or simple socket (avoid heavy deps)
        try:
            import socket
            for sub in wordlist:
                host = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(host)
                    found.append(host)
                except (socket.gaierror, OSError):
                    pass
        except Exception as e:
            logger.debug("Python DNS enum failed: %s", e)
    return [
        DiscoveredAsset(
            asset_type="subdomain",
            value=h,
            source="dns_brute",
            confidence="high",
            risk_impact="medium",
        )
        for h in sorted(set(found))
    ]


# ---------------------------------------------------------------------------
# WHOIS / passive DNS history (HackerTarget hostsearch)
# ---------------------------------------------------------------------------

def _whois_hostsearch_url(domain: str) -> str:
    return f"https://api.hackertarget.com/hostsearch/?q={domain}"

def enumerate_subdomains_whois(domain: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> list[DiscoveredAsset]:
    """Passive subdomain discovery via WHOIS/host history (HackerTarget)."""
    domain = (domain or "").strip().lower()
    if not domain or ".." in domain:
        return []
    assets: list[DiscoveredAsset] = []
    seen: set[str] = set()
    try:
        r = safe_get(_whois_hostsearch_url(domain), timeout=min(timeout, 8))
        if r.status_code != 200 or not r.text:
            return []
        for line in (r.text or "").strip().splitlines():
            part = line.split(",")[0].strip().lower()
            if not part or part in seen or not part.endswith(domain) and domain not in part:
                continue
            if "*." in part:
                part = part.replace("*.", "")
            if re.match(r"^[a-z0-9][a-z0-9.-]*$", part):
                seen.add(part)
                assets.append(DiscoveredAsset(
                    asset_type="subdomain",
                    value=part,
                    source="whois",
                    confidence="medium",
                    risk_impact="medium",
                ))
    except Exception as e:
        logger.warning("WHOIS hostsearch failed for %s: %s", domain, e)
    return assets


# ---------------------------------------------------------------------------
# GCP Storage (Google Cloud) + exposed API detection
# ---------------------------------------------------------------------------

def _gcp_bucket_exists(bucket: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> tuple[bool, bool]:
    """Check if GCS bucket exists and is listable. Returns (exists, listable). Uses safe_get for IP rotation."""
    try:
        url = f"https://storage.googleapis.com/{bucket}/"
        r = safe_get(url, timeout=min(timeout, 8))
        if r.status_code in (200, 403):
            return True, r.status_code == 200
        url2 = f"https://{bucket}.storage.googleapis.com/"
        r2 = safe_get(url2, timeout=min(timeout, 8))
        if r2.status_code in (200, 403):
            return True, r2.status_code == 200
        return False, False
    except Exception:
        return False, False


def scan_gcp_buckets(keywords: list[str], domain: str, timeout_per_check: int = 4) -> list[DiscoveredAsset]:
    """Discover GCP Storage buckets from domain/keywords. Enterprise: no hard cap; batch iteration."""
    assets: list[DiscoveredAsset] = []
    domain_clean = re.sub(r"[^a-z0-9-]", "", domain.split(".")[0].lower()) if domain else ""
    names: set[str] = set()
    if domain_clean:
        names.add(domain_clean)
        names.add(domain.replace(".", "-").lower()[:63])
    for kw in keywords or []:
        k = re.sub(r"[^a-z0-9-]", "", (kw or "").lower())[:63]
        if k:
            names.add(k)
    names_list = list(names)
    max_candidates = _recon_max_bucket_candidates()
    if max_candidates is not None:
        names_list = names_list[:max_candidates]
    batch = _recon_batch_size()
    for i in range(0, len(names_list), batch):
        for name in names_list[i : i + batch]:
            if not name:
                continue
            exists, listable = _gcp_bucket_exists(name, timeout=timeout_per_check)
            if exists:
                risk = "high" if listable else "medium"
                assets.append(DiscoveredAsset(
                    asset_type="gcp_bucket",
                    value=f"gs://{name}",
                    source="bucket_scan",
                    confidence="high",
                    risk_impact=risk,
                    extra={"listable": listable},
                ))
    return assets


def check_exposed_api_endpoints(base_urls: list[str], timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> list[DiscoveredAsset]:
    """
    Check common API/staging paths. Enterprise: no cap on base_urls; process in batches.
    """
    paths = ["/api", "/api/v1", "/graphql", "/swagger.json", "/api-docs", "/staging", "/dev", "/.env"]
    assets: list[DiscoveredAsset] = []
    bases = [b for b in (base_urls or []) if (b or "").rstrip("/") and "://" in (b or "")]
    batch = _recon_batch_size()
    for i in range(0, len(bases), batch):
        for base in bases[i : i + batch]:
            base = base.rstrip("/")
            for path in paths:
                try:
                    url = base + path
                    r = safe_get(url, timeout=min(timeout, 8))
                    if r.status_code == 200 and len(r.content) > 0:
                        assets.append(DiscoveredAsset(
                            asset_type="exposed_api",
                            value=url,
                            source="api_scan",
                            confidence="high",
                            risk_impact="high" if path in ("/.env", "/api", "/graphql") else "medium",
                            extra={"path": path, "status": r.status_code},
                        ))
                except Exception:
                    pass
    return assets


# ---------------------------------------------------------------------------
# Cloud Bucket Sniper (S3 + Azure Blob)
# ---------------------------------------------------------------------------

def _s3_bucket_exists(bucket: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> tuple[bool, bool]:
    """
    Check if S3 bucket exists and if it's listable (misconfigured).
    Returns (exists, listable).
    """
    try:
        url = f"https://{bucket}.s3.amazonaws.com/"
        r = safe_get(url, timeout=min(timeout, 8))
        if r.status_code in (200, 403):
            return True, r.status_code == 200
        if r.status_code == 404:
            return False, False
        # NoSuchBucket vs AccessDenied
        if "NoSuchBucket" in (r.text or ""):
            return False, False
        return True, "ListBucketResult" in (r.text or "") or r.status_code == 200
    except Exception:
        return False, False


def _azure_blob_exists(account: str, container: str, timeout: int = ENTERPRISE_HTTP_TIMEOUT) -> tuple[bool, bool]:
    """
    Check if Azure Blob container exists and is listable.
    Returns (exists, listable).
    """
    try:
        url = f"https://{account}.blob.core.windows.net/{container}?restype=container"
        r = safe_get(url, timeout=min(timeout, 8))
        if r.status_code in (200, 403):
            return True, r.status_code == 200
        return False, False
    except Exception:
        return False, False


def scan_cloud_buckets(
    keywords: list[str],
    domain: str,
    timeout_per_check: int = 4,
) -> list[DiscoveredAsset]:
    """
    Look for misconfigured S3 buckets and Azure Blobs. Enterprise: no hard cap; batch iteration.
    """
    assets: list[DiscoveredAsset] = []
    domain_clean = re.sub(r"[^a-z0-9-]", "", domain.split(".")[0].lower()) if domain else ""
    names: set[str] = set()
    if domain_clean:
        names.add(domain_clean)
        names.add(domain.replace(".", "-").lower()[:63])
    for kw in keywords or []:
        k = re.sub(r"[^a-z0-9-]", "", (kw or "").lower())[:63]
        if k:
            names.add(k)
    names_list = list(names)
    max_candidates = _recon_max_bucket_candidates()
    if max_candidates is not None:
        names_list = names_list[:max_candidates]
    batch = _recon_batch_size()
    # S3
    for i in range(0, len(names_list), batch):
        for name in names_list[i : i + batch]:
            if not name:
                continue
            exists, listable = _s3_bucket_exists(name, timeout=timeout_per_check)
            if exists:
                risk = "high" if listable else "medium"
                assets.append(DiscoveredAsset(
                    asset_type="s3_bucket",
                    value=f"s3://{name}",
                    source="bucket_scan",
                    confidence="high",
                    risk_impact=risk,
                    extra={"listable": listable},
                ))
    # Azure
    for i in range(0, len(names_list), batch):
        for name in names_list[i : i + batch]:
            if not name:
                continue
            for container in ("uploads", "backup", "data", "assets", "static", "logs", name):
                exists, listable = _azure_blob_exists(name, container, timeout=timeout_per_check)
                if exists:
                    risk = "high" if listable else "medium"
                    assets.append(DiscoveredAsset(
                        asset_type="azure_blob",
                        value=f"https://{name}.blob.core.windows.net/{container}",
                        source="bucket_scan",
                        confidence="high",
                        risk_impact=risk,
                        extra={"listable": listable},
                    ))
                    break
    return assets


# ---------------------------------------------------------------------------
# Full recon run & Shadow IT detection
# ---------------------------------------------------------------------------

def run_full_recon(
    domain: str,
    client_id: str,
    client_name: str,
    keywords: list[str] | None = None,
    use_ct: bool = True,
    use_dns_brute: bool = True,
    use_whois: bool = True,
    use_buckets: bool = True,
    use_gcp: bool = True,
    use_exposed_api: bool = False,
) -> list[DiscoveredAsset]:
    """
    Global reconnaissance: CT, WHOIS history, DNS brute, AWS/Azure/GCP buckets.
    Optionally check exposed API/staging endpoints on discovered subdomains.
    """
    all_assets: list[DiscoveredAsset] = []
    if use_ct:
        all_assets.extend(enumerate_subdomains_ct(domain))
    if use_whois:
        all_assets.extend(enumerate_subdomains_whois(domain))
    if use_dns_brute:
        all_assets.extend(enumerate_subdomains_dns(domain))
    if use_buckets:
        all_assets.extend(scan_cloud_buckets(keywords or [], domain))
    if use_gcp:
        all_assets.extend(scan_gcp_buckets(keywords or [], domain))
    if use_exposed_api:
        max_sub = _recon_max_subdomains()
        subdomains = [a.value for a in all_assets if a.asset_type == "subdomain"]
        if max_sub is not None:
            subdomains = subdomains[:max_sub]
        base_urls = [f"https://{s}" for s in subdomains]
        base_urls.append(f"https://{domain}")
        all_assets.extend(check_exposed_api_endpoints(base_urls))

    by_id: dict[str, DiscoveredAsset] = {}
    for a in all_assets:
        by_id[_normalize_asset_id(a)] = a
    return list(by_id.values())


def normalized_asset_ids(assets: list[DiscoveredAsset]) -> list[str]:
    """Return unique normalized IDs for snapshot storage."""
    return list({_normalize_asset_id(a) for a in assets})


def get_new_assets_for_discovery_alert(
    client_id: str,
    discovered: list[DiscoveredAsset],
) -> list[DiscoveredAsset]:
    """Return only assets not in the last snapshot (unknown / Shadow IT)."""
    from src.delta_scan import get_known_assets
    known = set(get_known_assets(client_id))
    return [a for a in discovered if _normalize_asset_id(a) not in known]
