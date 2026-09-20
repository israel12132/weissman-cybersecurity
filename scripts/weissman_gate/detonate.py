#!/usr/bin/env python3
"""Detonation farm lab — static analysis of a fetched URL.

Never executes the sample unless WEISSMAN_DETONATE_EXEC=1 AND bwrap or firejail
is on PATH. Isolated from fingerprint_engine verification_sandbox (heal).

The sample URL arrives in operator/attacker-supplied JSON, so the fetch path is
built on ``http.client`` with explicit validation instead of ``urllib.request``
(which opens ``file://`` URLs, follows redirects anywhere and lets whatever DNS
answers point the request at loopback or the cloud metadata service):

* scheme allow-list — http and https only;
* no userinfo, no whitespace or control characters, port in 1-65535;
* every address the host resolves to must be globally routable: loopback,
  RFC 1918, link-local (169.254.169.254 metadata), CGNAT, documentation,
  reserved, multicast and unspecified addresses are refused — set
  WEISSMAN_DETONATE_ALLOW_PRIVATE=1 in an isolated lab to permit private
  targets (multicast and unspecified stay refused);
* the TCP socket is opened on the exact address that passed the guard and only
  then handed to http.client, so a DNS rebind between validation and connect
  cannot swap the target; TLS is negotiated explicitly with the default
  verifying context and SNI for the URL's hostname;
* redirects are never auto-followed: at most MAX_REDIRECTS hops, each
  Location re-validated with the same rules;
* at most MAX_SAMPLE_BYTES are read (longer bodies are truncated, as before),
  with a SAMPLE_TIMEOUT_S timeout on every socket operation.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import shutil
import socket
import ssl
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urljoin, urlsplit

HOST = "127.0.0.1"
PORT = int(os.environ.get("WEISSMAN_DETONATION_PORT", "8745"))

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 3
MAX_SAMPLE_BYTES = 8_000_000
SAMPLE_TIMEOUT_S = 15.0
USER_AGENT = "weissman-detonation/1.0"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_READ_CHUNK = 64 * 1024
# Address classes that are refused even when private targets are allowed.
_NEVER_ALLOWED = ("multicast", "unspecified")


class SampleUrlError(ValueError):
    """The submitted sample URL failed validation (client error -> HTTP 400)."""


class SampleFetchError(RuntimeError):
    """The sample could not be fetched (resolution/transport/upstream error -> HTTP 502)."""


@dataclass(frozen=True)
class ValidatedTarget:
    """A sample URL that passed validation, with the vetted addresses to connect to."""

    url: str
    scheme: str
    host: str  # IDNA-encoded hostname: used for resolution, SNI and the Host header
    port: int
    request_target: str  # origin-form target for the request line: path[?query]
    addresses: tuple[tuple[int, int, int, tuple], ...]  # (family, type, proto, sockaddr) rows

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"


ConnectionFactory = Callable[[ValidatedTarget, float], http.client.HTTPConnection]


def address_rejection(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool = False) -> str | None:
    """Why ``ip`` may not be fetched from, or None when it is an acceptable target."""
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv4-mapped (::ffff:a.b.c.d) and 6to4 (2002::/16) addresses are judged by the
        # IPv4 address they embed as well, so ::ffff:127.0.0.1 is loopback, not "IPv6".
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is not None:
            reason = address_rejection(embedded, allow_private)
            if reason:
                return f"{reason} (embeds IPv4 {embedded})"
    if allow_private:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "not globally routable"
    return None


def _allow_private_from_env() -> bool:
    return os.environ.get("WEISSMAN_DETONATE_ALLOW_PRIVATE", "") == "1"


def resolve_sample_host(host: str, port: int, *, allow_private: bool = False) -> tuple[tuple[int, int, int, tuple], ...]:
    """Resolve ``host`` and vet every address it maps to.

    A name that maps to even one refused address is rejected as a whole: a resolver
    that alternates public and private answers is the classic DNS-rebinding setup.
    """
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SampleFetchError(f"could not resolve host {host!r}: {exc}") from exc
    vetted = []
    for family, socktype, proto, _canonname, sockaddr in rows:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            raise SampleUrlError(f"host {host!r} resolved to an unparseable address {sockaddr[0]!r}") from None
        reason = address_rejection(ip, allow_private)
        if reason:
            hint = ""
            if not allow_private and not reason.startswith(_NEVER_ALLOWED):
                hint = " (WEISSMAN_DETONATE_ALLOW_PRIVATE=1 permits private targets in an isolated lab)"
            raise SampleUrlError(f"host {host!r} resolves to {ip}, a {reason} address; refusing to fetch{hint}")
        vetted.append((family, socktype, proto, sockaddr))
    if not vetted:
        raise SampleFetchError(f"host {host!r} did not resolve to any address")
    return tuple(vetted)


def validate_sample_url(url: str, *, allow_private: bool | None = None) -> ValidatedTarget:
    """Validate a sample URL and resolve it to vetted addresses.

    Raises SampleUrlError for anything wrong with the URL itself (scheme, userinfo,
    host, port, characters) or with where it points (refused address classes), and
    SampleFetchError when the host cannot be resolved at all. ``allow_private``
    defaults to the WEISSMAN_DETONATE_ALLOW_PRIVATE=1 switch, read at call time.
    """
    if allow_private is None:
        allow_private = _allow_private_from_env()
    if not url:
        raise SampleUrlError("url required")
    if any(ch.isspace() or ord(ch) < 0x21 or ord(ch) == 0x7F for ch in url):
        raise SampleUrlError("url must not contain whitespace or control characters")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SampleUrlError(f"malformed url: {exc}") from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        shown = parts.scheme or "(none)"
        raise SampleUrlError(f"unsupported url scheme {shown!r}; allowed: http, https")
    if "@" in parts.netloc:
        raise SampleUrlError("url must not contain userinfo (user:password@host)")
    if not parts.hostname:
        raise SampleUrlError("url must include a hostname")
    try:
        host = parts.hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise SampleUrlError(f"hostname {parts.hostname!r} is not a valid IDNA name") from None
    try:
        port = parts.port
    except ValueError as exc:
        raise SampleUrlError(f"invalid port: {exc}") from None
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise SampleUrlError(f"invalid port {port}; expected 1-65535")
    request_target = parts.path or "/"
    if parts.query:
        request_target = f"{request_target}?{parts.query}"
    if not request_target.isascii():
        raise SampleUrlError("url path and query must be ASCII; percent-encode other characters")
    addresses = resolve_sample_host(host, port, allow_private=allow_private)
    return ValidatedTarget(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        request_target=request_target,
        addresses=addresses,
    )


def open_pinned_connection(target: ValidatedTarget, timeout: float = SAMPLE_TIMEOUT_S) -> http.client.HTTPConnection:
    """Open an HTTP(S) connection to one of ``target``'s vetted addresses.

    The socket is created from the already-resolved sockaddr — no second DNS lookup —
    so the peer is exactly the address that passed the guard. For https the socket is
    wrapped with the default verifying context (SNI and hostname check against the
    URL's host) before http.client sees it; http.client never calls connect() on a
    connection whose ``sock`` is already set, so a plain HTTPConnection carries TLS.
    """
    last_error: OSError | None = None
    for family, socktype, proto, sockaddr in target.addresses:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            if target.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target.host)
        except ssl.SSLError as exc:
            sock.close()
            raise SampleFetchError(f"tls handshake with {target.host} failed: {exc}") from exc
        except OSError as exc:
            sock.close()
            last_error = exc
            continue
        conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
        conn.sock = sock
        return conn
    raise SampleFetchError(f"could not connect to {target.host}:{target.port}: {last_error}")


def _read_capped(resp: http.client.HTTPResponse, max_bytes: int) -> bytes:
    chunks = []
    remaining = max_bytes
    while remaining > 0:
        chunk = resp.read(min(_READ_CHUNK, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def fetch_sample(
    url: str,
    *,
    timeout: float = SAMPLE_TIMEOUT_S,
    max_redirects: int = MAX_REDIRECTS,
    max_bytes: int = MAX_SAMPLE_BYTES,
    allow_private: bool | None = None,
    connect: ConnectionFactory | None = None,
) -> bytes:
    """Fetch a sample through the SSRF guard and return at most ``max_bytes`` of its body.

    Raises SampleUrlError when the submitted URL is invalid and SampleFetchError for
    everything that goes wrong after that: resolution, connect, TLS or HTTP failures,
    non-2xx answers, more than ``max_redirects`` hops, or a redirect to a target the
    guard refuses (the upstream, not the caller, chose that target).
    """
    if connect is None:
        connect = open_pinned_connection
    current = url
    for hop in range(max_redirects + 1):
        try:
            target = validate_sample_url(current, allow_private=allow_private)
        except SampleUrlError as exc:
            if hop == 0:
                raise
            raise SampleFetchError(f"redirect {hop} to {current!r} refused: {exc}") from exc
        try:
            conn = connect(target, timeout)
        except OSError as exc:
            raise SampleFetchError(f"could not connect to {target.host}:{target.port}: {exc}") from exc
        try:
            conn.request(
                "GET",
                target.request_target,
                headers={
                    "Host": target.host_header,
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            try:
                status, reason = resp.status, resp.reason
                location = resp.getheader("Location")
                body = _read_capped(resp, max_bytes) if 200 <= status < 300 else b""
            finally:
                resp.close()
        except (OSError, http.client.HTTPException) as exc:
            raise SampleFetchError(f"fetch of {current!r} failed: {exc}") from exc
        finally:
            conn.close()
        if status in REDIRECT_STATUSES:
            if not location:
                raise SampleFetchError(f"{current!r} answered HTTP {status} without a Location header")
            current = urljoin(current, location)
            continue
        if not 200 <= status < 300:
            raise SampleFetchError(f"{current!r} answered HTTP {status} {reason}".rstrip())
        return body
    raise SampleFetchError(f"too many redirects (limit {max_redirects}); last target {current!r}")


def analyze_bytes(blob: bytes, url: str) -> dict:
    sha = hashlib.sha256(blob).hexdigest()
    magic = "mz" if blob.startswith(b"MZ") else "elf" if blob.startswith(b"\x7fELF") else "other"
    strings = []
    current = bytearray()
    for b in blob[: 2_000_000]:
        if 32 <= b < 127:
            current.append(b)
        else:
            if len(current) >= 6:
                strings.append(current.decode("ascii", "ignore"))
            current.clear()
    iocs = [s for s in strings if s.startswith("http") or "cmd.exe" in s.lower() or "powershell" in s.lower()]
    result = {
        "ok": True,
        "url": url,
        "sha256": sha,
        "bytes": len(blob),
        "magic": magic,
        "ioc_strings": iocs[:40],
        "executed": False,
    }
    exec_flag = os.environ.get("WEISSMAN_DETONATE_EXEC", "") == "1"
    sandbox = shutil.which("bwrap") or shutil.which("firejail")
    if exec_flag and sandbox and magic in ("mz", "elf"):
        result["executed"] = False
        result["exec_detail"] = (
            f"{sandbox} present but PE/ELF execution is disabled in this lab until a Windows/Linux "
            "guest VM is attached — refusing to run unknown binaries on the Gate host."
        )
    elif exec_flag:
        result["exec_detail"] = "WEISSMAN_DETONATE_EXEC=1 but bwrap/firejail missing — not executing."
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send_json(200, {"ok": True, "component": "weissman-detonation"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        raw = self.rfile.read(n) if n > 0 else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        url = str(payload.get("url") or "").strip()
        if not url:
            return self._send_json(400, {"ok": False, "detail": "url required"})
        try:
            blob = fetch_sample(url)
        except SampleUrlError as exc:
            return self._send_json(400, {"ok": False, "detail": str(exc)})
        except SampleFetchError as exc:
            return self._send_json(502, {"ok": False, "detail": str(exc)})
        self._send_json(200, analyze_bytes(blob, url))


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"weissman-detonation http://{HOST}:{PORT}/", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
