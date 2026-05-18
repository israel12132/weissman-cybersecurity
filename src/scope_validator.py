"""
src/scope_validator.py
======================
Server-Side Request Forgery (SSRF) protection for scan endpoints.

Two-layer defence:
  1. Block any target whose hostname resolves to a private/reserved IP address
     (loopback, RFC-1918, link-local, metadata service IPs, IPv6 equivalents).
  2. Verify that the requested hostname belongs to a domain that is in-scope for
     the current tenant's approved clients (exact match or subdomain).

Usage in a route handler::

    from src.scope_validator import validate_scan_target, ScopeViolation

    @app.post("/api/command-center/scan")
    async def command_center_scan(body: ScanRequest, ...):
        try:
            validate_scan_target(body.target, tenant_id=tenant_id, db=db)
        except ScopeViolation as exc:
            return JSONResponse({"error": str(exc)}, status_code=403)
        ...

Set ``BYPASS_SSRF_CHECK=1`` **only** in isolated lab environments — never in
production.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
from urllib.parse import urlparse

logger = logging.getLogger("weissman.scope_validator")

# Explicitly blocked hostnames regardless of DNS resolution
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "169.254.169.254",          # AWS/Azure/GCP IMDS
        "metadata.google.internal", # GCP metadata
        "metadata.google",          # GCP metadata alias
        "169.254.170.2",            # ECS task metadata
    }
)

# RFC-1918, loopback, link-local, and other reserved/private blocks
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    # IPv4
    ipaddress.IPv4Network("127.0.0.0/8"),      # loopback
    ipaddress.IPv4Network("10.0.0.0/8"),        # RFC-1918 class A
    ipaddress.IPv4Network("172.16.0.0/12"),     # RFC-1918 class B
    ipaddress.IPv4Network("192.168.0.0/16"),    # RFC-1918 class C
    ipaddress.IPv4Network("169.254.0.0/16"),    # link-local / metadata
    ipaddress.IPv4Network("100.64.0.0/10"),     # shared address space (RFC 6598)
    ipaddress.IPv4Network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.IPv4Network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.IPv4Network("240.0.0.0/4"),       # reserved
    ipaddress.IPv4Network("0.0.0.0/8"),         # "this" network
    # IPv6
    ipaddress.IPv6Network("::1/128"),           # loopback
    ipaddress.IPv6Network("fc00::/7"),          # unique local
    ipaddress.IPv6Network("fe80::/10"),         # link-local
    ipaddress.IPv6Network("::ffff:0:0/96"),     # IPv4-mapped
    ipaddress.IPv6Network("::/128"),            # unspecified
)


class ScopeViolation(Exception):
    """Raised when a scan target fails SSRF or tenant-scope checks."""


def _is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is in any private/reserved network."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in _PRIVATE_NETWORKS:
        if addr in net:
            return True
    return False


def _resolve_hostname(hostname: str) -> list[str]:
    """Return all IP addresses that *hostname* resolves to (IPv4 + IPv6)."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return list({r[4][0] for r in results})
    except (socket.gaierror, OSError):
        return []


def _extract_hostname(target: str) -> str:
    """Extract the hostname component from a URL or bare domain string."""
    target = (target or "").strip()
    if "://" not in target:
        # Treat as URL with scheme so urlparse works correctly
        target = "https://" + target
    parsed = urlparse(target)
    return (parsed.hostname or "").lower().strip()


def check_ssrf(target: str) -> None:
    """
    Raise :class:`ScopeViolation` if *target* resolves to a private/reserved
    address or is an explicitly blocked hostname.

    Parameters
    ----------
    target:
        URL or hostname to validate (e.g. ``"https://example.com/api"`` or
        ``"example.com"``).

    Raises
    ------
    ScopeViolation
        If the target resolves to a private/reserved IP or is blocked.
    """
    if os.getenv("BYPASS_SSRF_CHECK", "0").strip() == "1":
        logger.warning(
            "BYPASS_SSRF_CHECK is enabled — skipping SSRF check for %s. "
            "NEVER set this in production.",
            target,
        )
        return

    hostname = _extract_hostname(target)
    if not hostname:
        raise ScopeViolation(f"Cannot parse hostname from target: {target!r}")

    # 1a. Block explicitly listed hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        raise ScopeViolation(
            f"Scan target {hostname!r} is an explicitly blocked hostname."
        )

    # 1b. Block numeric IPs that are private (before DNS lookup)
    try:
        ipaddress.ip_address(hostname)
        # It is a numeric IP — check it directly
        if _is_private_ip(hostname):
            raise ScopeViolation(
                f"Scan target {hostname!r} resolves to a private/reserved IP address."
            )
        return
    except ValueError:
        pass  # Not a numeric IP; fall through to DNS resolution

    # 1c. Resolve and check all returned IPs
    resolved = _resolve_hostname(hostname)
    if not resolved:
        raise ScopeViolation(
            f"Cannot resolve hostname {hostname!r} — target is unreachable or invalid."
        )
    for ip in resolved:
        if _is_private_ip(ip):
            raise ScopeViolation(
                f"Scan target {hostname!r} resolves to private/reserved IP {ip}. "
                "SSRF attempt blocked."
            )


def check_tenant_scope(target: str, db_session, tenant_id: str) -> None:
    """
    Verify that *target*'s hostname matches an approved domain for *tenant_id*.

    Fetches all clients belonging to the tenant from the database and checks
    whether the target hostname exactly matches or is a subdomain of any of
    those clients' registered domains.

    Parameters
    ----------
    target:
        URL or hostname supplied by the user.
    db_session:
        Active SQLAlchemy session.
    tenant_id:
        The tenant performing the scan.

    Raises
    ------
    ScopeViolation
        If the target does not match any approved client domain for the tenant.
    """
    hostname = _extract_hostname(target)
    if not hostname:
        raise ScopeViolation(f"Cannot parse hostname from target: {target!r}")

    try:
        from src.database import ClientModel  # imported here to avoid circular imports

        clients = (
            db_session.query(ClientModel)
            .filter(ClientModel.tenant_id == tenant_id)
            .all()
        )

        approved_domains: set[str] = set()
        for client in clients:
            scope = client.scope or {}
            if isinstance(scope, str):
                try:
                    scope = json.loads(scope)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "check_tenant_scope: malformed scope JSON for client %s: %s",
                        getattr(client, "id", "?"), exc,
                    )
                    scope = {}
            for domain in scope.get("domains") or []:
                domain = (domain or "").strip().lower()
                if domain and not domain.startswith("*"):
                    approved_domains.add(domain)

        if not approved_domains:
            raise ScopeViolation(
                f"No approved client domains found for tenant {tenant_id!r}. "
                "Add clients with domains before scanning."
            )

        # Exact match or subdomain match
        for domain in approved_domains:
            if hostname == domain or hostname.endswith("." + domain):
                return

        raise ScopeViolation(
            f"Scan target {hostname!r} is not in scope for tenant {tenant_id!r}. "
            "Only approved client domains may be scanned."
        )

    except ScopeViolation:
        raise
    except Exception as exc:
        logger.warning("check_tenant_scope: DB lookup failed (%s) — blocking scan", exc)
        raise ScopeViolation(
            f"Unable to verify scope for target {hostname!r}: {exc}"
        ) from exc


def validate_scan_target(
    target: str,
    tenant_id: str | None = None,
    db_session=None,
) -> None:
    """
    Full SSRF + scope validation for a scan target.

    Performs the SSRF check unconditionally, then the tenant-scope check when
    both *tenant_id* and *db_session* are provided.

    Parameters
    ----------
    target:
        URL or hostname to validate.
    tenant_id:
        Current tenant identifier (required for scope check).
    db_session:
        Active SQLAlchemy session (required for scope check).

    Raises
    ------
    ScopeViolation
        On any SSRF or out-of-scope violation.
    """
    check_ssrf(target)

    if tenant_id is not None and db_session is not None:
        check_tenant_scope(target, db_session, tenant_id)
