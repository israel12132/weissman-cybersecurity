"""Active tech stack fingerprinting via Rust engine. Discovers technologies from target URLs.
Phase 3: If Rust binary is missing or fails, log critical warning and use Python header fallback.
"""
import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

def _fingerprint_binary() -> Path | None:
    """Path to fingerprint_engine binary (debug or release)."""
    base = Path(__file__).resolve().parent.parent / "fingerprint_engine"
    for name in ["target/release/fingerprint_engine", "target/debug/fingerprint_engine"]:
        p = base / name
        if p.exists():
            return p
    return None


def _fingerprint_single_url_python(url: str, timeout: int = 8) -> list[str]:
    """
    Phase 3 fallback: minimal tech stack from Server and X-Powered-By headers only.
    Ensures scan can proceed when Rust engine is unavailable.
    """
    techs: list[str] = []
    try:
        import requests
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Weissman-Scanner/1.0)"},
            allow_redirects=True,
        )
        server = (r.headers.get("Server") or "").strip()
        if server:
            # e.g. "nginx/1.18.0" -> nginx, "Apache/2.4" -> apache
            techs.append(server.split("/")[0].strip().lower() or server.lower())
        powered = (r.headers.get("X-Powered-By") or "").strip()
        if powered:
            # e.g. "PHP/8.1", "Express" -> php, express
            techs.append(powered.split("/")[0].strip().lower() or powered.lower())
        techs = list(dict.fromkeys(t for t in techs if t and len(t) >= 2))
    except Exception as e:
        logger.debug("Python fingerprint fallback for %s: %s", url[:60], e)
    return techs


def fingerprint_urls_python_fallback(urls: list[str]) -> dict[str, list[str]]:
    """Phase 3: when Rust binary is missing or fails, use requests + Server/X-Powered-By only."""
    result: dict[str, list[str]] = {}
    for u in urls:
        if not (u or "").strip():
            continue
        url = u.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        result[url] = _fingerprint_single_url_python(url)
    return result


def fingerprint_urls(urls: list[str]) -> dict[str, list[str]]:
    """
    Call Rust fingerprint engine for each URL; returns map url -> [tech1, tech2, ...].
    Phase 3: If binary missing or execution fails, log critical and use Python header fallback.
    """
    if not urls:
        return {}
    urls = [u.strip() for u in urls if u and u.strip()]
    if not urls:
        return {}
    bin_path = _fingerprint_binary()
    if not bin_path:
        logger.critical(
            "fingerprint_engine binary missing. Using Python fallback (Server/X-Powered-By only). "
            "Build with: cd fingerprint_engine && cargo build --release"
        )
        return fingerprint_urls_python_fallback(urls)
    try:
        proc = subprocess.run(
            [str(bin_path)] + urls,
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(bin_path.parent.parent),
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            logger.critical(
                "fingerprint_engine failed (returncode=%s). Using Python fallback.", proc.returncode
            )
            return fingerprint_urls_python_fallback(urls)
        out = json.loads(proc.stdout)
        if not isinstance(out, dict):
            logger.critical("fingerprint_engine returned invalid JSON. Using Python fallback.")
            return fingerprint_urls_python_fallback(urls)
        return {k: v if isinstance(v, list) else [] for k, v in out.items()}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError) as e:
        logger.critical("fingerprint_engine execution failed: %s. Using Python fallback.", e)
        return fingerprint_urls_python_fallback(urls)


def run_fuzzer_binary(
    target_url: str,
    base_payload: str = '{"email":"test@test.com"}',
    notify_url: str | None = None,
    tech_stack: list[str] | None = None,
) -> bool:
    """
    Run the Rust API fuzzer on target_url. If tech_stack is provided, writes
    AI-guided payloads to a temp file and sets FUZZ_PAYLOADS_FILE for contextual fuzzing.
    Reports are written to project_root/reports/ (CWD set so Python dashboard finds them).
    """
    bin_path = _fingerprint_binary()
    if not bin_path:
        logger.critical("fingerprint_engine binary missing; cannot run fuzzer. Build with: cd fingerprint_engine && cargo build --release")
        return False
    url = (target_url or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        url = f"https://{url}" if url else ""
    if not url:
        logger.warning("run_fuzzer_binary: empty target_url")
        return False
    env = os.environ.copy()
    if notify_url:
        env["NOTIFY_URL"] = notify_url
    else:
        logger.warning("run_fuzzer_binary: NOTIFY_URL not set; Python callback for report will not be called")
    payloads_file = None
    if tech_stack:
        try:
            from src.agent_redteam import write_fuzzer_payloads_file
            payloads_file = write_fuzzer_payloads_file(tech_stack)
            if payloads_file:
                env["FUZZ_PAYLOADS_FILE"] = payloads_file
                logger.info("fuzzer: using guided payloads from %s", payloads_file)
        except Exception as e:
            logger.warning("fuzzer: failed to write payloads file: %s", e)
    project_root = Path(__file__).resolve().parent.parent
    cwd = str(project_root)
    try:
        logger.info("fuzzer: starting target=%s notify_url=%s cwd=%s", url, notify_url or "(none)", cwd)
        subprocess.Popen(
            [str(bin_path), "fuzz", url, base_payload],
            cwd=cwd,
            stdout=None,
            stderr=None,
            env=env,
        )
        return True
    except (FileNotFoundError, OSError) as e:
        logger.critical("fuzzer execution failed: %s", e)
        return False


def fingerprint_ip_ranges(ip_ranges: list[str], deep: bool = False) -> dict[str, list[str]]:
    """
    Call Rust fingerprint engine to scan IP ranges (CIDR).
    Default: ports 80, 443, 8080. With deep=True (or WEISSMAN_DEEP_SCAN=1): Top 1000 Nmap ports.
    Returns map url -> [tech1, tech2, ...]. Phase 3: log critical if binary missing.
    """
    if not ip_ranges:
        return {}
    cidrs = [r.strip() for r in ip_ranges if r and str(r).strip()]
    if not cidrs:
        return {}
    bin_path = _fingerprint_binary()
    if not bin_path:
        logger.critical("fingerprint_engine binary missing; cannot scan IP ranges. Build with: cd fingerprint_engine && cargo build --release")
        return {}
    cmd = [str(bin_path), "ips"]
    if deep or (os.getenv("WEISSMAN_DEEP_SCAN") or "").strip().lower() in ("1", "true", "yes"):
        cmd.append("--deep")
    cmd.extend(cidrs)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300 if deep else 120,
            cwd=str(bin_path.parent.parent),
            env={**os.environ},
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}
        out = json.loads(proc.stdout)
        if not isinstance(out, dict):
            return {}
        return {k: v if isinstance(v, list) else [] for k, v in out.items()}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError) as e:
        logger.critical("fingerprint_engine ips failed: %s", e)
        return {}


def run_safe_probe(url: str, tech_hint: str = "") -> dict | None:
    """
    Run Rust safe-probe: non-destructive check for header/timing behavior without running payloads.
    Returns dict with header_changed, timing_anomaly, baseline_latency_ms, probe_latency_ms, etc.
    """
    bin_path = _fingerprint_binary()
    if not bin_path:
        logger.critical("fingerprint_engine binary missing; safe-probe unavailable.")
        return None
    url = (url or "").strip()
    if not url or not url.startswith(("http://", "https://")):
        url = f"https://{url}" if url else ""
    if not url:
        return None
    try:
        proc = subprocess.run(
            [str(bin_path), "safe-probe", url, (tech_hint or "").strip()],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(bin_path.parent.parent),
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        out = json.loads(proc.stdout)
        if isinstance(out, dict) and "error" not in out:
            return out
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError) as e:
        logger.critical("safe-probe execution failed: %s", e)
        return None


def merge_fingerprint_into_scope(
    scope: dict,
    fingerprint_result: dict[str, list[str]],
) -> list[str]:
    """
    Merge fingerprinted techs from all URLs into a single list (no duplicates).
    scope has domains; fingerprint_result is url -> [techs]. Returns combined tech_stack.
    """
    existing = set()
    for t in scope.get("tech_stack") or []:
        if t and str(t).strip():
            existing.add(str(t).strip().lower())
    for _url, techs in fingerprint_result.items():
        for t in techs or []:
            if t and str(t).strip():
                existing.add(str(t).strip().lower())
    return sorted(existing)
