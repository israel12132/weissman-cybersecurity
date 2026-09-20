#!/usr/bin/env python3
"""Identity-aware reverse proxy lab (ZTNA/SWG starter).

Requires Authorization: Bearer <token> matching WEISSMAN_ZTNA_TOKEN.
Forwards to WEISSMAN_ZTNA_UPSTREAM. Fails closed if token unset.

Forwarding is one explicit ``http.client`` exchange rather than ``urllib.request``:

* WEISSMAN_ZTNA_UPSTREAM is parsed once at import — http or https, a host, an
  optional port and path prefix, nothing else — and the proxy refuses to start
  on anything it does not understand;
* the client's request target is validated before it is forwarded: origin-form
  only (exactly one leading "/", so ``//evil`` and ``http://evil/`` never reach
  the upstream), printable ASCII, at most MAX_TARGET_BYTES;
* the Host header sent upstream is always the configured upstream, and only the
  client's Accept header is relayed;
* no upstream-controlled bytes are ever written into a response header: the
  Content-Type is re-emitted from a fixed table of media types (anything else
  degrades to application/octet-stream) and Location is withheld, so a redirect
  from the upstream is relayed as its status and body but never followed and
  never re-pointed by the proxy;
* TLS to an https upstream uses the default verifying context with TLS 1.2 as
  the floor; the bearer token is compared with hmac.compare_digest.
"""
from __future__ import annotations

import hmac
import http.client
import json
import os
import re
import socket
import ssl
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = int(os.environ.get("WEISSMAN_ZTNA_PORT", "8744"))
UPSTREAM = os.environ.get("WEISSMAN_ZTNA_UPSTREAM", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("WEISSMAN_ZTNA_TOKEN", "").strip()

UPSTREAM_TIMEOUT_S = 8.0
MAX_TARGET_BYTES = 8 * 1024
DEFAULT_PORTS = {"http": 80, "https": 443}
# Printable ASCII with no whitespace: the only characters the upstream URL may contain
# (http.client refuses control characters and cannot encode non-ASCII at all).
_PRINTABLE_NO_SPACE = re.compile(r"[\x21-\x7e]*")
# Origin-form request target: exactly one leading "/" — "//host" would be read as a
# scheme-relative URL by the upstream — followed by printable ASCII only.
_ORIGIN_FORM = re.compile(r"/(?!/)[\x21-\x7e]*")
# Header values we relay upstream: visible ASCII plus space, so no CR/LF and no
# obs-fold can be smuggled through the proxy.
_HEADER_VALUE = re.compile(r"[\x20-\x7e]+")
# Media types the proxy re-emits to the client. The response header is built from the
# constant in this table, never from the upstream's bytes; anything not listed is served
# as application/octet-stream. A charset parameter is likewise re-emitted only from a
# fixed set.
DEFAULT_CONTENT_TYPE = "application/octet-stream"
RELAYED_MEDIA_TYPES = {
    name: name
    for name in (
        "application/json",
        "application/problem+json",
        "application/javascript",
        "application/xml",
        "application/pdf",
        "application/zip",
        "application/octet-stream",
        "text/plain",
        "text/html",
        "text/css",
        "text/csv",
        "text/xml",
        "text/event-stream",
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/svg+xml",
        "image/webp",
    )
}
RELAYED_CHARSETS = {name: name for name in ("utf-8", "us-ascii", "iso-8859-1")}


class UpstreamConfigError(ValueError):
    """WEISSMAN_ZTNA_UPSTREAM is not an http(s)://host[:port][/prefix] URL."""


class RequestTargetError(ValueError):
    """The client's request target may not be forwarded; ``status`` is the reply code."""

    def __init__(self, detail: str, status: int = 400):
        super().__init__(detail)
        self.status = status


@dataclass(frozen=True)
class Upstream:
    scheme: str
    host: str
    port: int
    path_prefix: str = ""  # "" or "/prefix" without a trailing slash

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"


def parse_upstream(value: str) -> Upstream:
    """Parse WEISSMAN_ZTNA_UPSTREAM strictly; raise UpstreamConfigError on anything else."""
    if not value:
        raise UpstreamConfigError("WEISSMAN_ZTNA_UPSTREAM is empty")
    if not _PRINTABLE_NO_SPACE.fullmatch(value):
        raise UpstreamConfigError("WEISSMAN_ZTNA_UPSTREAM must be printable ASCII without whitespace")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise UpstreamConfigError(f"WEISSMAN_ZTNA_UPSTREAM is malformed: {exc}") from None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        shown = parts.scheme or "(none)"
        raise UpstreamConfigError(f"WEISSMAN_ZTNA_UPSTREAM scheme must be http or https, got {shown!r}")
    if "@" in parts.netloc:
        raise UpstreamConfigError("WEISSMAN_ZTNA_UPSTREAM must not contain userinfo")
    if not parts.hostname:
        raise UpstreamConfigError("WEISSMAN_ZTNA_UPSTREAM must include a host")
    if parts.query or parts.fragment:
        raise UpstreamConfigError("WEISSMAN_ZTNA_UPSTREAM must not contain a query string or fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise UpstreamConfigError(f"WEISSMAN_ZTNA_UPSTREAM port is invalid: {exc}") from None
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise UpstreamConfigError(f"WEISSMAN_ZTNA_UPSTREAM port {port} is out of range 1-65535")
    return Upstream(scheme=scheme, host=parts.hostname, port=port, path_prefix=parts.path.rstrip("/"))


try:
    UPSTREAM_TARGET = parse_upstream(UPSTREAM)
except UpstreamConfigError as exc:
    raise SystemExit(f"weissman-ztna: refusing to start: {exc}") from None


def validate_request_target(path: str) -> str:
    """Return ``path`` if it may be forwarded as an origin-form request target."""
    if len(path) > MAX_TARGET_BYTES:
        raise RequestTargetError(f"request target exceeds {MAX_TARGET_BYTES} bytes", status=414)
    if not _ORIGIN_FORM.fullmatch(path):
        raise RequestTargetError(
            "request target must be an origin-form path: exactly one leading '/', "
            "printable ASCII, no whitespace or control characters"
        )
    return path


def bearer_token_matches(authorization: str, expected: str) -> bool:
    """Constant-time check of an ``Authorization: Bearer <token>`` value against ``expected``."""
    scheme, _, credential = authorization.partition(" ")
    if scheme != "Bearer" or not credential or not expected:
        return False
    return hmac.compare_digest(credential.encode("utf-8"), expected.encode("utf-8"))


def open_upstream_connection(upstream: Upstream, timeout: float = UPSTREAM_TIMEOUT_S) -> http.client.HTTPConnection:
    """Connect to the configured upstream; https is negotiated with the verifying context (TLS >= 1.2)."""
    sock = socket.create_connection((upstream.host, upstream.port), timeout=timeout)
    try:
        if upstream.scheme == "https":
            sock = tls_context().wrap_socket(sock, server_hostname=upstream.host)
    except OSError:
        sock.close()
        raise
    conn = http.client.HTTPConnection(upstream.host, upstream.port, timeout=timeout)
    conn.sock = sock
    return conn


def relayable_header(value: str | None) -> str | None:
    """The header value if it is plain visible ASCII, else None (dropped, never relayed)."""
    if value is None or not _HEADER_VALUE.fullmatch(value):
        return None
    return value


def relayed_content_type(value: str | None) -> str:
    """Map the upstream Content-Type onto a constant from RELAYED_MEDIA_TYPES.

    Only the table's own strings are ever returned, so the client-facing header carries
    no upstream-controlled bytes (a response-splitting or MIME-confusion vector otherwise).
    """
    if not value:
        return DEFAULT_CONTENT_TYPE
    media, _, params = value.partition(";")
    canonical = RELAYED_MEDIA_TYPES.get(media.strip().lower())
    if canonical is None:
        return DEFAULT_CONTENT_TYPE
    for param in params.split(";"):
        key, _, raw = param.partition("=")
        if key.strip().lower() == "charset":
            charset = RELAYED_CHARSETS.get(raw.strip().strip('"').lower())
            if charset is not None:
                return f"{canonical}; charset={charset}"
            break
    return canonical


def tls_context() -> ssl.SSLContext:
    """The default verifying context with TLS 1.2 as an explicit floor."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _deny(self, code: int, detail: str):
        body = json.dumps({"ok": False, "detail": detail}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            if not TOKEN:
                return self._deny(503, "WEISSMAN_ZTNA_TOKEN unset — proxy will not forward")
            body = json.dumps({"ok": True, "component": "weissman-ztna", "upstream": UPSTREAM}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        auth = self.headers.get("Authorization", "")
        if not TOKEN:
            return self._deny(503, "WEISSMAN_ZTNA_TOKEN unset — fail closed")
        if not bearer_token_matches(auth, TOKEN):
            return self._deny(401, "missing or invalid bearer token")
        try:
            path = validate_request_target(self.path)
        except RequestTargetError as exc:
            return self._deny(exc.status, str(exc))
        headers = {
            "Host": UPSTREAM_TARGET.host_header,
            "Accept": relayable_header(self.headers.get("Accept")) or "*/*",
        }
        try:
            conn = open_upstream_connection(UPSTREAM_TARGET, UPSTREAM_TIMEOUT_S)
        except OSError as exc:
            return self._deny(502, str(exc))
        try:
            conn.request("GET", UPSTREAM_TARGET.path_prefix + path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            content_type = relayed_content_type(resp.getheader("Content-Type"))
            data = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            return self._deny(502, str(exc))
        finally:
            conn.close()
        # Status and body are relayed as-is; headers are not. Location in particular is
        # withheld: a 3xx reaches the client as its status and body, and the proxy neither
        # follows the redirect nor re-points the client at an upstream-chosen URL.
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self._deny(405, "POST not enabled on lab ZTNA proxy")


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"weissman-ztna http://{HOST}:{PORT}/ -> {UPSTREAM}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
