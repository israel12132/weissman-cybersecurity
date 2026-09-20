"""
tests/unit/test_weissman_gate_fetch.py
======================================
Unit tests for the Weissman Gate lab fetch paths:

* scripts/weissman_gate/detonate.py  — SSRF-guarded sample fetch
  (validate_sample_url / open_pinned_connection / fetch_sample / POST handler)
* scripts/weissman_gate/ztna_proxy.py — strict upstream parsing, request-target
  validation, constant-time bearer check, relay that never follows redirects

The modules are stand-alone lab daemons (not a package), so they are loaded straight
from scripts/weissman_gate/ with importlib, with their environment set before loading.
No network is used: socket.getaddrinfo, socket.socket / socket.create_connection,
ssl.create_default_context and the connection factories are replaced with in-memory
fakes, and the HTTP handlers are driven through a fake client socket.

Run with: pytest tests/unit/test_weissman_gate_fetch.py -v
"""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import ipaddress
import json
import socket
import ssl
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Iterator

import pytest

def _gate_dir(pytestconfig) -> Path:
    """scripts/weissman_gate under pytest's rootdir (the checkout root holding pytest.ini).

    Anchored on pytest rather than ``__file__``: tests/ is reached through a symlink in
    this checkout, and ``Path(__file__).resolve()`` would follow it out of the tree
    that holds scripts/.
    """
    gate_dir = Path(pytestconfig.rootpath) / "scripts" / "weissman_gate"
    assert (gate_dir / "detonate.py").is_file(), f"gate scripts not found under {gate_dir}"
    return gate_dir

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
ZTNA_TOKEN = "s3cret-lab-token"


# ---------------------------------------------------------------------------
# module loading (env is applied BEFORE the module executes)
# ---------------------------------------------------------------------------

def _load_module(gate_dir: Path, alias: str, filename: str, env: dict[str, str | None]) -> ModuleType:
    """Load <gate_dir>/<filename> under ``alias`` with ``env`` applied first."""
    with pytest.MonkeyPatch.context() as mp:
        for key, value in env.items():
            if value is None:
                mp.delenv(key, raising=False)
            else:
                mp.setenv(key, value)
        spec = importlib.util.spec_from_file_location(alias, gate_dir / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(alias, None)
            raise
    return module


@pytest.fixture(scope="module")
def detonate(pytestconfig) -> Iterator[ModuleType]:
    module = _load_module(
        _gate_dir(pytestconfig),
        "weissman_gate_detonate_under_test",
        "detonate.py",
        {"WEISSMAN_DETONATE_ALLOW_PRIVATE": None, "WEISSMAN_DETONATE_EXEC": None},
    )
    yield module
    sys.modules.pop(module.__name__, None)


@pytest.fixture(scope="module")
def ztna(pytestconfig) -> Iterator[ModuleType]:
    module = _load_module(
        _gate_dir(pytestconfig),
        "weissman_gate_ztna_under_test",
        "ztna_proxy.py",
        {"WEISSMAN_ZTNA_TOKEN": ZTNA_TOKEN, "WEISSMAN_ZTNA_UPSTREAM": "http://127.0.0.1:8000"},
    )
    yield module
    sys.modules.pop(module.__name__, None)


@pytest.fixture(scope="module")
def ztna_no_token(pytestconfig) -> Iterator[ModuleType]:
    module = _load_module(
        _gate_dir(pytestconfig),
        "weissman_gate_ztna_no_token_under_test",
        "ztna_proxy.py",
        {"WEISSMAN_ZTNA_TOKEN": None, "WEISSMAN_ZTNA_UPSTREAM": "http://127.0.0.1:8000"},
    )
    yield module
    sys.modules.pop(module.__name__, None)


# ---------------------------------------------------------------------------
# fakes: resolver, sockets, TLS context, HTTP connections, client socket
# ---------------------------------------------------------------------------

class FakeResolver:
    """socket.getaddrinfo stand-in: IP literals resolve to themselves, names via ``table``."""

    def __init__(self, table: dict[str, list[str]] | None = None):
        self.table = dict(table or {})
        self.calls: list[tuple[str, int]] = []

    def __call__(self, host, port, family=0, type=0, proto=0, flags=0):
        self.calls.append((host, port))
        try:
            ips = [str(ipaddress.ip_address(host))]
        except ValueError:
            ips = self.table.get(host)
        if not ips:
            raise socket.gaierror(socket.EAI_NONAME, f"Name or service not known: {host}")
        rows = []
        for ip in ips:
            if ipaddress.ip_address(ip).version == 4:
                rows.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)))
            else:
                rows.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0)))
        return rows


@pytest.fixture
def resolver(monkeypatch) -> FakeResolver:
    fake = FakeResolver(
        {
            "sample.example": [PUBLIC_V4],
            "dual.example": [PUBLIC_V4, PUBLIC_V6],
            "poisoned.example": [PUBLIC_V4, "10.0.0.5"],
            "meta.example": ["169.254.169.254"],
        }
    )
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


class FakeSocket:
    def __init__(self, family=-1, type=-1, proto=-1, refuse=()):
        self.family, self.type, self.proto = family, type, proto
        self.refuse = set(refuse)
        self.timeout = None
        self.peer = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        if address in self.refuse:
            raise ConnectionRefusedError(111, f"refused: {address}")
        self.peer = address

    def close(self):
        self.closed = True


class FakeSocketFactory:
    """socket.socket stand-in recording every socket it hands out."""

    def __init__(self, refuse=()):
        self.refuse = tuple(refuse)
        self.sockets: list[FakeSocket] = []

    def __call__(self, family=-1, type=-1, proto=-1, fileno=None):
        sock = FakeSocket(family, type, proto, self.refuse)
        self.sockets.append(sock)
        return sock


class FakeTlsSocket:
    def __init__(self, inner, server_hostname):
        self.inner = inner
        self.server_hostname = server_hostname
        self.closed = False

    def close(self):
        self.closed = True


class FakeTlsContext:
    """ssl.create_default_context() stand-in that records how sockets are wrapped."""

    def __init__(self, error: BaseException | None = None):
        self.error = error
        self.wrapped: list[FakeTlsSocket] = []

    def wrap_socket(self, sock, server_hostname=None, **kwargs):
        if self.error is not None:
            raise self.error
        tls = FakeTlsSocket(sock, server_hostname)
        self.wrapped.append(tls)
        return tls


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None, reason="OK"):
        self.status = status
        self.reason = reason
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = io.BytesIO(body)
        self.closed = False

    def getheader(self, name, default=None):
        return self._headers.get(name.lower(), default)

    def read(self, amt=None):
        return self._body.read(amt)

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.requests: list[tuple[str, str, dict]] = []
        self.closed = False

    def request(self, method, url, body=None, headers=None):
        self.requests.append((method, url, dict(headers or {})))

    def getresponse(self):
        if self.error is not None:
            raise self.error
        return self.response

    def close(self):
        self.closed = True


class ScriptedConnector:
    """Connection factory handing out one scripted step (response, connection or error) per hop."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.targets: list = []
        self.connections: list[FakeConnection] = []

    def __call__(self, target, timeout):
        self.targets.append((target, timeout))
        assert self.steps, "more connections were opened than the test scripted"
        step = self.steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        conn = FakeConnection(step) if isinstance(step, FakeResponse) else step
        self.connections.append(conn)
        return conn


class FakeClientSocket:
    """Just enough of a socket for BaseHTTPRequestHandler: a readable request, a writable reply."""

    def __init__(self, request: bytes):
        self._request = io.BytesIO(request)
        self.sent = bytearray()

    def makefile(self, mode, *args, **kwargs):
        assert "r" in mode
        return self._request

    def sendall(self, data):
        self.sent += data


class _ReplySocket:
    def __init__(self, raw: bytes):
        self._raw = raw

    def makefile(self, mode, *args, **kwargs):
        return io.BytesIO(self._raw)


def run_handler(module, request_line: str, headers: dict[str, str] | None = None, body: bytes = b""):
    """Drive module.Handler with one raw request; return (status, lower-cased headers, body)."""
    head = [request_line] + [f"{k}: {v}" for k, v in (headers or {}).items()]
    raw = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body
    sock = FakeClientSocket(raw)
    module.Handler(sock, ("127.0.0.1", 40000), SimpleNamespace())
    reply = http.client.HTTPResponse(_ReplySocket(bytes(sock.sent)))
    try:
        reply.begin()
        return reply.status, {k.lower(): v for k, v in reply.getheaders()}, reply.read()
    finally:
        reply.close()


# ===========================================================================
# detonate.py — validate_sample_url
# ===========================================================================

class TestValidateSampleUrl:
    def test_rejects_file_scheme(self, detonate, resolver):
        with pytest.raises(detonate.SampleUrlError, match="unsupported url scheme 'file'"):
            detonate.validate_sample_url("file:///etc/passwd")
        assert resolver.calls == []

    def test_rejects_ftp_scheme(self, detonate, resolver):
        with pytest.raises(detonate.SampleUrlError, match="unsupported url scheme 'ftp'"):
            detonate.validate_sample_url("ftp://sample.example/x")
        assert resolver.calls == []

    @pytest.mark.parametrize("url", ["", "sample.example/x", "//sample.example/x", "javascript:alert(1)"])
    def test_rejects_missing_or_unknown_scheme(self, detonate, resolver, url):
        with pytest.raises(detonate.SampleUrlError):
            detonate.validate_sample_url(url)

    def test_rejects_userinfo(self, detonate, resolver):
        with pytest.raises(detonate.SampleUrlError, match="userinfo"):
            detonate.validate_sample_url("http://user:pw@sample.example/x")
        with pytest.raises(detonate.SampleUrlError, match="userinfo"):
            detonate.validate_sample_url("http://sample.example@10.0.0.1/x")
        assert resolver.calls == []

    @pytest.mark.parametrize(
        "url, reason",
        [
            ("http://127.0.0.1/", "loopback"),
            ("http://127.1.2.3:8000/admin", "loopback"),
            ("http://[::1]/", "loopback"),
            ("http://10.0.0.1/", "private"),
            ("http://172.16.5.5/", "private"),
            ("http://192.168.1.1/", "private"),
            ("http://169.254.169.254/latest/meta-data/", "link-local"),
            ("http://[fe80::1]/", "link-local"),
            ("http://[::ffff:127.0.0.1]/", "loopback"),
            ("http://[::ffff:10.0.0.1]/", "private"),
            ("http://100.64.0.1/", "not globally routable"),
            ("http://0.0.0.0/", "unspecified"),
            ("http://224.0.0.1/", "multicast"),
            ("http://240.0.0.1/", "reserved"),
            ("http://[fc00::1]/", "private"),
        ],
    )
    def test_rejects_non_public_literals_by_default(self, detonate, resolver, url, reason):
        with pytest.raises(detonate.SampleUrlError, match=reason):
            detonate.validate_sample_url(url)

    def test_rejects_name_that_resolves_to_link_local(self, detonate, resolver):
        with pytest.raises(detonate.SampleUrlError, match="169.254.169.254, a link-local"):
            detonate.validate_sample_url("http://meta.example/")
        assert resolver.calls == [("meta.example", 80)]

    def test_name_with_one_private_answer_is_rejected_as_a_whole(self, detonate, resolver):
        with pytest.raises(detonate.SampleUrlError, match="10.0.0.5"):
            detonate.validate_sample_url("http://poisoned.example/")

    def test_env_flag_allows_private_targets(self, detonate, resolver, monkeypatch):
        monkeypatch.setenv("WEISSMAN_DETONATE_ALLOW_PRIVATE", "1")
        target = detonate.validate_sample_url("http://10.0.0.1:8080/sample.bin")
        assert target.addresses[0][3] == ("10.0.0.1", 8080)
        assert detonate.validate_sample_url("http://127.0.0.1/").host == "127.0.0.1"
        assert detonate.validate_sample_url("http://169.254.169.254/").host == "169.254.169.254"

    def test_env_flag_is_read_at_call_time(self, detonate, resolver, monkeypatch):
        monkeypatch.setenv("WEISSMAN_DETONATE_ALLOW_PRIVATE", "1")
        detonate.validate_sample_url("http://10.0.0.1/")
        monkeypatch.delenv("WEISSMAN_DETONATE_ALLOW_PRIVATE")
        with pytest.raises(detonate.SampleUrlError, match="private"):
            detonate.validate_sample_url("http://10.0.0.1/")

    def test_explicit_argument_overrides_env(self, detonate, resolver, monkeypatch):
        monkeypatch.setenv("WEISSMAN_DETONATE_ALLOW_PRIVATE", "1")
        with pytest.raises(detonate.SampleUrlError, match="private"):
            detonate.validate_sample_url("http://10.0.0.1/", allow_private=False)

    @pytest.mark.parametrize("url", ["http://224.0.0.1/", "http://0.0.0.0/", "http://[ff02::1]/"])
    def test_multicast_and_unspecified_stay_refused_with_flag(self, detonate, resolver, monkeypatch, url):
        monkeypatch.setenv("WEISSMAN_DETONATE_ALLOW_PRIVATE", "1")
        with pytest.raises(detonate.SampleUrlError):
            detonate.validate_sample_url(url)

    def test_public_target_is_fully_described(self, detonate, resolver):
        target = detonate.validate_sample_url("HTTPS://Sample.Example:8443/dir/file.exe?x=1&y=2#frag")
        assert target.scheme == "https"
        assert target.host == "sample.example"
        assert target.port == 8443
        assert target.request_target == "/dir/file.exe?x=1&y=2"
        assert target.host_header == "sample.example:8443"
        assert target.addresses == ((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, (PUBLIC_V4, 8443)),)
        assert resolver.calls == [("sample.example", 8443)]

    def test_default_port_and_root_path(self, detonate, resolver):
        target = detonate.validate_sample_url("http://sample.example")
        assert (target.port, target.request_target, target.host_header) == (80, "/", "sample.example")
        assert detonate.validate_sample_url("https://sample.example").port == 443

    def test_ipv6_literal_host_header_is_bracketed(self, detonate, resolver):
        target = detonate.validate_sample_url(f"http://[{PUBLIC_V6}]:8080/")
        assert target.host_header == f"[{PUBLIC_V6}]:8080"
        assert target.addresses[0][0] == socket.AF_INET6

    def test_idna_hostname_is_encoded(self, detonate, resolver, monkeypatch):
        resolver.table["xn--bcher-kva.example"] = [PUBLIC_V4]
        target = detonate.validate_sample_url("http://bücher.example/")
        assert target.host == "xn--bcher-kva.example"
        assert target.host_header == "xn--bcher-kva.example"

    @pytest.mark.parametrize(
        "url",
        ["http://sample.example/a b", "http://sample.example/\x01", "http://sample.example/x\r\nHost: evil", "http://sam ple.example/"],
    )
    def test_rejects_whitespace_and_control_characters(self, detonate, resolver, url):
        with pytest.raises(detonate.SampleUrlError, match="whitespace or control"):
            detonate.validate_sample_url(url)
        assert resolver.calls == []

    def test_rejects_non_ascii_path(self, detonate, resolver):
        with pytest.raises(detonate.SampleUrlError, match="ASCII"):
            detonate.validate_sample_url("http://sample.example/päth")

    @pytest.mark.parametrize("url", ["http://sample.example:99999/", "http://sample.example:0/", "http://sample.example:abc/"])
    def test_rejects_bad_ports(self, detonate, resolver, url):
        with pytest.raises(detonate.SampleUrlError, match="port"):
            detonate.validate_sample_url(url)

    @pytest.mark.parametrize("url", ["http:///path", "http://", "http://[::1/"])
    def test_rejects_missing_or_malformed_host(self, detonate, resolver, url):
        with pytest.raises(detonate.SampleUrlError):
            detonate.validate_sample_url(url)

    def test_unresolvable_host_is_a_fetch_error(self, detonate, resolver):
        with pytest.raises(detonate.SampleFetchError, match="could not resolve host 'nx.example'"):
            detonate.validate_sample_url("http://nx.example/")


# ===========================================================================
# detonate.py — open_pinned_connection
# ===========================================================================

class TestOpenPinnedConnection:
    def test_connects_to_the_vetted_sockaddr_without_re_resolving(self, detonate, resolver, monkeypatch):
        sockets = FakeSocketFactory()
        monkeypatch.setattr(socket, "socket", sockets)
        target = detonate.validate_sample_url("http://sample.example:8080/x")
        lookups_before = len(resolver.calls)
        conn = detonate.open_pinned_connection(target, 15.0)
        assert isinstance(conn, http.client.HTTPConnection)
        assert conn.sock is sockets.sockets[0]
        assert sockets.sockets[0].peer == (PUBLIC_V4, 8080)
        assert sockets.sockets[0].timeout == 15.0
        assert (sockets.sockets[0].family, sockets.sockets[0].type) == (socket.AF_INET, socket.SOCK_STREAM)
        assert len(resolver.calls) == lookups_before
        conn.close()

    def test_falls_through_to_the_next_vetted_address(self, detonate, resolver, monkeypatch):
        sockets = FakeSocketFactory(refuse=[(PUBLIC_V4, 80)])
        monkeypatch.setattr(socket, "socket", sockets)
        target = detonate.validate_sample_url("http://dual.example/")
        conn = detonate.open_pinned_connection(target, 15.0)
        assert sockets.sockets[0].closed is True
        assert conn.sock is sockets.sockets[1]
        assert sockets.sockets[1].peer == (PUBLIC_V6, 80, 0, 0)
        conn.close()

    def test_all_addresses_refused_is_a_fetch_error(self, detonate, resolver, monkeypatch):
        sockets = FakeSocketFactory(refuse=[(PUBLIC_V4, 80), (PUBLIC_V6, 80, 0, 0)])
        monkeypatch.setattr(socket, "socket", sockets)
        target = detonate.validate_sample_url("http://dual.example/")
        with pytest.raises(detonate.SampleFetchError, match="could not connect to dual.example:80"):
            detonate.open_pinned_connection(target, 15.0)
        assert all(s.closed for s in sockets.sockets)

    def test_https_wraps_the_pinned_socket_with_sni_for_the_url_host(self, detonate, resolver, monkeypatch):
        sockets = FakeSocketFactory()
        context = FakeTlsContext()
        monkeypatch.setattr(socket, "socket", sockets)
        monkeypatch.setattr(ssl, "create_default_context", lambda: context)
        target = detonate.validate_sample_url("https://sample.example/x")
        conn = detonate.open_pinned_connection(target, 15.0)
        assert isinstance(conn, http.client.HTTPConnection)
        assert conn.sock is context.wrapped[0]
        assert context.wrapped[0].inner is sockets.sockets[0]
        assert context.wrapped[0].server_hostname == "sample.example"
        assert sockets.sockets[0].peer == (PUBLIC_V4, 443)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        conn.close()

    def test_tls_context_pins_tls12_floor_on_the_real_default_context(self, detonate):
        ctx = detonate.tls_context()
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True

    def test_tls_failure_closes_the_socket_and_is_a_fetch_error(self, detonate, resolver, monkeypatch):
        sockets = FakeSocketFactory()
        context = FakeTlsContext(error=ssl.SSLCertVerificationError("certificate verify failed"))
        monkeypatch.setattr(socket, "socket", sockets)
        monkeypatch.setattr(ssl, "create_default_context", lambda: context)
        target = detonate.validate_sample_url("https://sample.example/x")
        with pytest.raises(detonate.SampleFetchError, match="tls handshake with sample.example failed"):
            detonate.open_pinned_connection(target, 15.0)
        assert sockets.sockets[0].closed is True


# ===========================================================================
# detonate.py — fetch_sample
# ===========================================================================

class TestFetchSample:
    def test_sends_host_user_agent_and_reads_body(self, detonate, resolver):
        connector = ScriptedConnector(FakeResponse(200, body=b"MZ\x90\x00payload"))
        blob = detonate.fetch_sample("http://sample.example/x?y=1", connect=connector)
        assert blob == b"MZ\x90\x00payload"
        target, timeout = connector.targets[0]
        assert (target.host, target.port, timeout) == ("sample.example", 80, detonate.SAMPLE_TIMEOUT_S)
        conn = connector.connections[0]
        assert conn.requests == [
            (
                "GET",
                "/x?y=1",
                {"Host": "sample.example", "User-Agent": detonate.USER_AGENT, "Accept": "*/*", "Connection": "close"},
            )
        ]
        assert conn.closed is True and conn.response.closed is True

    def test_follows_at_most_three_redirects_revalidating_each(self, detonate, resolver):
        connector = ScriptedConnector(
            FakeResponse(302, headers={"Location": "/hop1"}),
            FakeResponse(301, headers={"Location": "https://sample.example:8443/hop2"}),
            FakeResponse(307, headers={"Location": "hop3"}),
            FakeResponse(200, body=b"final"),
        )
        assert detonate.fetch_sample("http://sample.example/start", connect=connector) == b"final"
        assert [t.request_target for t, _ in connector.targets] == ["/start", "/hop1", "/hop2", "/hop3"]
        assert [(t.scheme, t.port) for t, _ in connector.targets] == [("http", 80), ("http", 80), ("https", 8443), ("https", 8443)]
        assert resolver.calls == [("sample.example", 80), ("sample.example", 80), ("sample.example", 8443), ("sample.example", 8443)]
        assert all(c.closed for c in connector.connections)

    def test_stops_after_the_redirect_limit(self, detonate, resolver):
        hops = [FakeResponse(302, headers={"Location": f"/hop{i}"}) for i in range(4)]
        connector = ScriptedConnector(*hops, FakeResponse(200, body=b"never"))
        with pytest.raises(detonate.SampleFetchError, match="too many redirects \\(limit 3\\)"):
            detonate.fetch_sample("http://sample.example/", connect=connector)
        assert len(connector.connections) == 4  # initial request + 3 redirects, the 5th is never opened
        assert detonate.MAX_REDIRECTS == 3

    def test_redirect_to_forbidden_address_is_refused(self, detonate, resolver):
        connector = ScriptedConnector(
            FakeResponse(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}),
            FakeResponse(200, body=b"never"),
        )
        with pytest.raises(detonate.SampleFetchError, match="redirect 1 .* refused: .*link-local"):
            detonate.fetch_sample("http://sample.example/", connect=connector)
        assert len(connector.connections) == 1

    def test_redirect_to_file_scheme_is_refused(self, detonate, resolver):
        connector = ScriptedConnector(FakeResponse(302, headers={"Location": "file:///etc/passwd"}))
        with pytest.raises(detonate.SampleFetchError, match="refused: unsupported url scheme 'file'"):
            detonate.fetch_sample("http://sample.example/", connect=connector)
        assert len(connector.connections) == 1

    def test_redirect_without_location_is_a_fetch_error(self, detonate, resolver):
        connector = ScriptedConnector(FakeResponse(302))
        with pytest.raises(detonate.SampleFetchError, match="without a Location header"):
            detonate.fetch_sample("http://sample.example/", connect=connector)

    def test_byte_cap_truncates_the_body(self, detonate, resolver):
        connector = ScriptedConnector(FakeResponse(200, body=b"A" * 1500))
        assert len(detonate.fetch_sample("http://sample.example/", connect=connector, max_bytes=1000)) == 1000

    def test_default_byte_cap_is_eight_million(self, detonate, resolver):
        assert detonate.MAX_SAMPLE_BYTES == 8_000_000
        connector = ScriptedConnector(FakeResponse(200, body=b"\x00" * (detonate.MAX_SAMPLE_BYTES + 1)))
        assert len(detonate.fetch_sample("http://sample.example/", connect=connector)) == detonate.MAX_SAMPLE_BYTES

    def test_non_2xx_is_a_fetch_error(self, detonate, resolver):
        connector = ScriptedConnector(FakeResponse(404, body=b"nope", reason="Not Found"))
        with pytest.raises(detonate.SampleFetchError, match="HTTP 404 Not Found"):
            detonate.fetch_sample("http://sample.example/", connect=connector)

    def test_connect_error_is_a_fetch_error(self, detonate, resolver):
        connector = ScriptedConnector(ConnectionRefusedError(111, "Connection refused"))
        with pytest.raises(detonate.SampleFetchError, match="could not connect to sample.example:80"):
            detonate.fetch_sample("http://sample.example/", connect=connector)

    def test_protocol_error_is_a_fetch_error_and_closes_the_connection(self, detonate, resolver):
        broken = FakeConnection(error=http.client.RemoteDisconnected("Remote end closed connection"))
        connector = ScriptedConnector(broken)
        with pytest.raises(detonate.SampleFetchError, match="failed: Remote end closed"):
            detonate.fetch_sample("http://sample.example/", connect=connector)
        assert broken.closed is True

    def test_invalid_submitted_url_raises_url_error_before_any_connection(self, detonate, resolver):
        connector = ScriptedConnector()
        with pytest.raises(detonate.SampleUrlError):
            detonate.fetch_sample("http://127.0.0.1:8000/", connect=connector)
        assert connector.targets == []


# ===========================================================================
# detonate.py — POST handler status mapping and result shape
# ===========================================================================

def _post_detonate(detonate, payload):
    body = json.dumps(payload).encode()
    headers = {"Host": "127.0.0.1", "Content-Type": "application/json", "Content-Length": str(len(body))}
    status, reply_headers, reply_body = run_handler(detonate, "POST /detonate HTTP/1.1", headers, body)
    assert reply_headers["content-type"] == "application/json"
    assert reply_headers["content-length"] == str(len(reply_body))
    return status, json.loads(reply_body)


class TestDetonateHandler:
    def test_get_health(self, detonate):
        status, headers, body = run_handler(detonate, "GET / HTTP/1.1", {"Host": "127.0.0.1"})
        assert status == 200
        assert json.loads(body) == {"ok": True, "component": "weissman-detonation"}

    @pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": None}, {"other": 1}])
    def test_missing_url_is_400(self, detonate, resolver, payload):
        assert _post_detonate(detonate, payload) == (400, {"ok": False, "detail": "url required"})

    def test_non_object_or_malformed_body_is_400_not_a_crash(self, detonate, resolver):
        for body in (b"[1,2]", b"not json", b"\xff\xfe"):
            headers = {"Host": "127.0.0.1", "Content-Length": str(len(body))}
            status, _, reply = run_handler(detonate, "POST / HTTP/1.1", headers, body)
            assert (status, json.loads(reply)) == (400, {"ok": False, "detail": "url required"})

    @pytest.mark.parametrize(
        "url, needle",
        [
            ("file:///etc/passwd", "unsupported url scheme 'file'"),
            ("http://127.0.0.1:8000/admin", "loopback"),
            ("http://169.254.169.254/latest/meta-data/", "link-local"),
            ("http://user:pw@sample.example/", "userinfo"),
        ],
    )
    def test_validation_failure_is_400_with_detail(self, detonate, resolver, url, needle):
        status, data = _post_detonate(detonate, {"url": url})
        assert status == 400
        assert data["ok"] is False and needle in data["detail"]

    def test_fetch_failure_is_502_with_detail(self, detonate, resolver, monkeypatch):
        monkeypatch.setattr(detonate, "open_pinned_connection", ScriptedConnector(ConnectionRefusedError(111, "Connection refused")))
        status, data = _post_detonate(detonate, {"url": "http://sample.example/x.exe"})
        assert status == 502
        assert data["ok"] is False and "could not connect to sample.example:80" in data["detail"]

    def test_success_keeps_the_analyze_bytes_shape(self, detonate, resolver, monkeypatch):
        body = b"MZ\x00\x00http://c2.example/beacon\x00powershell -enc AAAA\x00short\x00"
        monkeypatch.setattr(detonate, "open_pinned_connection", ScriptedConnector(FakeResponse(200, body=body)))
        status, data = _post_detonate(detonate, {"url": "http://sample.example/x.exe", "source": "weissman-malware_detonation"})
        assert status == 200
        assert set(data) == {"ok", "url", "sha256", "bytes", "magic", "ioc_strings", "executed"}
        assert data["ok"] is True
        assert data["url"] == "http://sample.example/x.exe"
        assert data["sha256"] == hashlib.sha256(body).hexdigest()
        assert data["bytes"] == len(body)
        assert data["magic"] == "mz"
        assert data["ioc_strings"] == ["http://c2.example/beacon", "powershell -enc AAAA"]
        assert data["executed"] is False


# ===========================================================================
# ztna_proxy.py — upstream configuration
# ===========================================================================

class TestParseUpstream:
    def test_default_upstream(self, ztna):
        upstream = ztna.parse_upstream("http://127.0.0.1:8000")
        assert (upstream.scheme, upstream.host, upstream.port, upstream.path_prefix) == ("http", "127.0.0.1", 8000, "")
        assert upstream.host_header == "127.0.0.1:8000"
        assert ztna.UPSTREAM_TARGET == upstream
        assert ztna.UPSTREAM == "http://127.0.0.1:8000"

    def test_https_default_port_and_prefix(self, ztna):
        upstream = ztna.parse_upstream("https://API.Example/base/")
        assert (upstream.scheme, upstream.host, upstream.port, upstream.path_prefix) == ("https", "api.example", 443, "/base")
        assert upstream.host_header == "api.example"

    def test_ipv6_literal(self, ztna):
        upstream = ztna.parse_upstream("http://[::1]:8000")
        assert (upstream.host, upstream.port, upstream.host_header) == ("::1", 8000, "[::1]:8000")

    @pytest.mark.parametrize(
        "value, needle",
        [
            ("", "empty"),
            ("ftp://127.0.0.1:21", "scheme must be http or https"),
            ("127.0.0.1:8000", "scheme must be http or https"),
            ("http://user:pw@127.0.0.1:8000", "userinfo"),
            ("http://", "include a host"),
            ("http://127.0.0.1:8000?x=1", "query string"),
            ("http://127.0.0.1:8000#frag", "query string or fragment"),
            ("http://127.0.0.1:99999", "port"),
            ("http://127.0.0.1:0", "port"),
            ("http://127.0.0.1:abc", "port"),
            ("http://127.0.0.1:8000/a b", "printable ASCII"),
            ("http://127.0.0.1:8000/\x01", "printable ASCII"),
            ("http://[::1:8000", "malformed"),
        ],
    )
    def test_rejects_anything_else(self, ztna, value, needle):
        with pytest.raises(ztna.UpstreamConfigError, match=needle):
            ztna.parse_upstream(value)

    @pytest.mark.parametrize(
        "value, needle",
        [("ftp://127.0.0.1:21", "scheme must be http or https"), ("http://u:p@127.0.0.1:8000", "userinfo")],
    )
    def test_refuses_to_start_on_a_bad_upstream(self, pytestconfig, value, needle):
        alias = "weissman_gate_ztna_bad_upstream_under_test"
        env = {"WEISSMAN_ZTNA_TOKEN": ZTNA_TOKEN, "WEISSMAN_ZTNA_UPSTREAM": value}
        with pytest.raises(SystemExit, match=f"weissman-ztna: refusing to start: .*{needle}"):
            _load_module(_gate_dir(pytestconfig), alias, "ztna_proxy.py", env)
        assert alias not in sys.modules


# ===========================================================================
# ztna_proxy.py — request-target validation and bearer check
# ===========================================================================

class TestValidateRequestTarget:
    @pytest.mark.parametrize("path", ["/", "/api/health", "/api/v1/items?x=1&y=%2F", "/a/b/c.json", "/~user/(x)!$&'*+,;=:@"])
    def test_accepts_origin_form_targets(self, ztna, path):
        assert ztna.validate_request_target(path) == path

    @pytest.mark.parametrize(
        "path",
        ["//evil", "//evil.example/x", "///evil", "http://evil/", "https://evil.example/x", "evil", "", "*", "/a\x01b", "/a\x7fb", "/a b", "/a\tb", "/a\r\nHost: evil", "/a\xe9b", "\\evil"],
    )
    def test_rejects_non_origin_form_targets(self, ztna, path):
        with pytest.raises(ztna.RequestTargetError, match="origin-form") as excinfo:
            ztna.validate_request_target(path)
        assert excinfo.value.status == 400

    def test_rejects_targets_over_8_kib(self, ztna):
        assert ztna.validate_request_target("/" + "x" * 8191)
        with pytest.raises(ztna.RequestTargetError, match="exceeds 8192 bytes") as excinfo:
            ztna.validate_request_target("/" + "x" * 8192)
        assert excinfo.value.status == 414


class TestBearerTokenMatches:
    def test_exact_match(self, ztna):
        assert ztna.bearer_token_matches(f"Bearer {ZTNA_TOKEN}", ZTNA_TOKEN) is True

    @pytest.mark.parametrize(
        "authorization",
        ["", "Bearer", "Bearer ", f"Bearer {ZTNA_TOKEN}x", f"Bearer {ZTNA_TOKEN[:-1]}", f"bearer {ZTNA_TOKEN}", f"Basic {ZTNA_TOKEN}", f"Bearer  {ZTNA_TOKEN}", ZTNA_TOKEN],
    )
    def test_rejects_wrong_or_malformed_credentials(self, ztna, authorization):
        assert ztna.bearer_token_matches(authorization, ZTNA_TOKEN) is False

    def test_never_matches_when_no_token_is_configured(self, ztna):
        assert ztna.bearer_token_matches("Bearer ", "") is False
        assert ztna.bearer_token_matches("Bearer x", "") is False


# ===========================================================================
# ztna_proxy.py — handler behaviour
# ===========================================================================

def _get(module, target, authorization=None, accept=None):
    headers = {"Host": "127.0.0.1:8744"}
    if authorization is not None:
        headers["Authorization"] = authorization
    if accept is not None:
        headers["Accept"] = accept
    return run_handler(module, f"GET {target} HTTP/1.1", headers)


GOOD_AUTH = f"Bearer {ZTNA_TOKEN}"


class TestZtnaHandler:
    @pytest.mark.parametrize("target", ["/", "/health"])
    def test_health_is_unauthenticated_and_names_the_upstream(self, ztna, monkeypatch, target):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector())
        status, headers, body = _get(ztna, target)
        assert status == 200
        assert headers["content-type"] == "application/json"
        assert json.loads(body) == {"ok": True, "component": "weissman-ztna", "upstream": "http://127.0.0.1:8000"}

    @pytest.mark.parametrize("target", ["/", "/health"])
    def test_health_is_503_when_token_unset(self, ztna_no_token, monkeypatch, target):
        monkeypatch.setattr(ztna_no_token, "open_upstream_connection", ScriptedConnector())
        status, _, body = _get(ztna_no_token, target)
        assert status == 503
        assert json.loads(body) == {"ok": False, "detail": "WEISSMAN_ZTNA_TOKEN unset — proxy will not forward"}

    def test_unset_token_fails_closed_before_forwarding(self, ztna_no_token, monkeypatch):
        monkeypatch.setattr(ztna_no_token, "open_upstream_connection", ScriptedConnector())
        status, _, body = _get(ztna_no_token, "/api/health", authorization="Bearer anything")
        assert status == 503
        assert json.loads(body) == {"ok": False, "detail": "WEISSMAN_ZTNA_TOKEN unset — fail closed"}

    @pytest.mark.parametrize("authorization", [None, "", "Bearer wrong", f"bearer {ZTNA_TOKEN}", f"Bearer {ZTNA_TOKEN}x", ZTNA_TOKEN])
    def test_wrong_or_missing_token_is_401_without_forwarding(self, ztna, monkeypatch, authorization):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector())
        status, _, body = _get(ztna, "/api/health", authorization=authorization)
        assert status == 401
        assert json.loads(body) == {"ok": False, "detail": "missing or invalid bearer token"}

    def test_forwards_with_upstream_host_and_default_accept(self, ztna, monkeypatch):
        connector = ScriptedConnector(FakeResponse(200, body=b'{"ok":true}', headers={"Content-Type": "application/json"}))
        monkeypatch.setattr(ztna, "open_upstream_connection", connector)
        status, headers, body = _get(ztna, "/api/health?deep=1", authorization=GOOD_AUTH)
        assert (status, headers["content-type"], body) == (200, "application/json", b'{"ok":true}')
        assert "location" not in headers
        upstream, timeout = connector.targets[0]
        assert upstream == ztna.UPSTREAM_TARGET and timeout == ztna.UPSTREAM_TIMEOUT_S
        conn = connector.connections[0]
        assert conn.requests == [("GET", "/api/health?deep=1", {"Host": "127.0.0.1:8000", "Accept": "*/*"})]
        assert conn.closed is True

    def test_relays_the_client_accept_header_only(self, ztna, monkeypatch):
        connector = ScriptedConnector(FakeResponse(200, body=b"ok", headers={"Content-Type": "text/plain"}))
        monkeypatch.setattr(ztna, "open_upstream_connection", connector)
        status, headers, body = _get(ztna, "/api/health", authorization=GOOD_AUTH, accept="text/plain, */*;q=0.1")
        assert (status, headers["content-type"], body) == (200, "text/plain", b"ok")
        _, _, forwarded = connector.connections[0].requests[0]
        assert forwarded == {"Host": "127.0.0.1:8000", "Accept": "text/plain, */*;q=0.1"}

    def test_upstream_without_content_type_defaults_to_octet_stream(self, ztna, monkeypatch):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector(FakeResponse(200, body=b"\x00\x01")))
        status, headers, body = _get(ztna, "/blob", authorization=GOOD_AUTH)
        assert (status, headers["content-type"], body) == (200, "application/octet-stream", b"\x00\x01")

    @pytest.mark.parametrize("target", ["http://evil/", "https://evil.example/x", "/a\x01b", "/a\x7fb", "/a\xe9b", "\\evil"])
    def test_rejects_bad_request_targets_without_forwarding(self, ztna, monkeypatch, target):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector())
        status, _, body = _get(ztna, target, authorization=GOOD_AUTH)
        assert status == 400
        assert json.loads(body)["ok"] is False and "origin-form" in json.loads(body)["detail"]

    @pytest.mark.parametrize("target", ["//evil", "//evil.example/x", "///evil"])
    def test_scheme_relative_targets_never_reach_the_upstream(self, ztna, monkeypatch, target):
        # Python >= 3.9.3 http.server already collapses a leading "//" to "/"; the validator
        # is the guard on interpreters that do not. Either way nothing scheme-relative goes out.
        connector = ScriptedConnector(FakeResponse(200, body=b"ok", headers={"Content-Type": "text/plain"}))
        monkeypatch.setattr(ztna, "open_upstream_connection", connector)
        status, _, _ = _get(ztna, target, authorization=GOOD_AUTH)
        forwarded = [url for conn in connector.connections for _, url, _ in conn.requests]
        assert status in (200, 400)
        assert all(url.startswith("/") and not url.startswith("//") for url in forwarded)
        if status == 400:
            assert forwarded == []

    def test_over_long_target_is_414(self, ztna, monkeypatch):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector())
        status, _, body = _get(ztna, "/" + "x" * 9000, authorization=GOOD_AUTH)
        assert status == 414
        assert json.loads(body) == {"ok": False, "detail": "request target exceeds 8192 bytes"}

    def test_relays_redirect_status_without_following_or_re_pointing(self, ztna, monkeypatch):
        connector = ScriptedConnector(
            FakeResponse(302, body=b"", headers={"Location": "https://elsewhere.example/login", "Content-Type": "text/html"}),
            FakeResponse(200, body=b"never"),
        )
        monkeypatch.setattr(ztna, "open_upstream_connection", connector)
        status, headers, body = _get(ztna, "/api/login", authorization=GOOD_AUTH)
        assert (status, headers["content-type"], body) == (302, "text/html", b"")
        # The upstream never gets to write a response header: Location is withheld.
        assert "location" not in headers
        assert len(connector.connections) == 1

    @pytest.mark.parametrize(
        ("upstream_value", "relayed"),
        [
            ("application/json", "application/json"),
            ("Application/JSON; charset=UTF-8", "application/json; charset=utf-8"),
            ('text/html; charset="iso-8859-1"', "text/html; charset=iso-8859-1"),
            ("text/plain; charset=utf-7", "text/plain"),
            ("text/plain; boundary=x", "text/plain"),
            ("application/x-custom", "application/octet-stream"),
            ("text/html\r\nX-Injected: 1", "application/octet-stream"),
            ("", "application/octet-stream"),
            (None, "application/octet-stream"),
        ],
    )
    def test_content_type_is_re_emitted_from_the_fixed_table(self, ztna, upstream_value, relayed):
        out = ztna.relayed_content_type(upstream_value)
        assert out == relayed
        # Whatever is emitted is one of the table's media types (plus a charset from the
        # fixed charset set) — never the upstream's own string.
        media, _, charset = out.partition("; charset=")
        assert media in ztna.RELAYED_MEDIA_TYPES
        assert not charset or charset in ztna.RELAYED_CHARSETS

    def test_unlisted_content_type_never_reaches_the_client_header(self, ztna, monkeypatch):
        connector = ScriptedConnector(FakeResponse(200, body=b"x", headers={"Content-Type": "text/html\r\nSet-Cookie: a=b"}))
        monkeypatch.setattr(ztna, "open_upstream_connection", connector)
        status, headers, body = _get(ztna, "/api/x", authorization=GOOD_AUTH)
        assert (status, headers["content-type"], body) == (200, "application/octet-stream", b"x")
        assert "set-cookie" not in headers

    def test_relays_upstream_error_status_and_body(self, ztna, monkeypatch):
        connector = ScriptedConnector(FakeResponse(404, body=b'{"error":"nope"}', headers={"Content-Type": "application/json"}, reason="Not Found"))
        monkeypatch.setattr(ztna, "open_upstream_connection", connector)
        status, headers, body = _get(ztna, "/api/missing", authorization=GOOD_AUTH)
        assert (status, headers["content-type"], body) == (404, "application/json", b'{"error":"nope"}')

    def test_drops_header_values_with_crlf(self, ztna, monkeypatch):
        assert ztna.relayable_header("text/plain") == "text/plain"
        assert ztna.relayable_header("") is None
        assert ztna.relayable_header(None) is None
        assert ztna.relayable_header("x\r\n y") is None
        assert ztna.relayable_header("caf\xe9") is None

    def test_unreachable_upstream_is_502(self, ztna, monkeypatch):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector(ConnectionRefusedError(111, "Connection refused")))
        status, _, body = _get(ztna, "/api/health", authorization=GOOD_AUTH)
        assert status == 502
        data = json.loads(body)
        assert data["ok"] is False and "Connection refused" in data["detail"]

    def test_protocol_error_is_502_and_closes_the_connection(self, ztna, monkeypatch):
        broken = FakeConnection(error=http.client.RemoteDisconnected("Remote end closed connection"))
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector(broken))
        status, _, body = _get(ztna, "/api/health", authorization=GOOD_AUTH)
        assert status == 502
        assert "Remote end closed" in json.loads(body)["detail"]
        assert broken.closed is True

    def test_post_is_405(self, ztna, monkeypatch):
        monkeypatch.setattr(ztna, "open_upstream_connection", ScriptedConnector())
        status, _, body = run_handler(ztna, "POST /api/health HTTP/1.1", {"Host": "x", "Authorization": GOOD_AUTH, "Content-Length": "0"})
        assert status == 405
        assert json.loads(body) == {"ok": False, "detail": "POST not enabled on lab ZTNA proxy"}


# ===========================================================================
# ztna_proxy.py — upstream connection factory
# ===========================================================================

class TestOpenUpstreamConnection:
    def test_http_uses_a_plain_socket(self, ztna, monkeypatch):
        created = []

        def fake_create_connection(address, timeout=None):
            sock = FakeSocket()
            sock.peer, sock.timeout = address, timeout
            created.append(sock)
            return sock

        monkeypatch.setattr(socket, "create_connection", fake_create_connection)
        conn = ztna.open_upstream_connection(ztna.parse_upstream("http://127.0.0.1:8000"), 8.0)
        assert isinstance(conn, http.client.HTTPConnection)
        assert conn.sock is created[0]
        assert (created[0].peer, created[0].timeout) == (("127.0.0.1", 8000), 8.0)
        conn.close()

    def test_https_wraps_with_sni_for_the_upstream_host(self, ztna, monkeypatch):
        created = []
        context = FakeTlsContext()

        def fake_create_connection(address, timeout=None):
            sock = FakeSocket()
            sock.peer = address
            created.append(sock)
            return sock

        monkeypatch.setattr(socket, "create_connection", fake_create_connection)
        monkeypatch.setattr(ssl, "create_default_context", lambda: context)
        conn = ztna.open_upstream_connection(ztna.parse_upstream("https://api.example"), 8.0)
        assert conn.sock is context.wrapped[0]
        assert context.wrapped[0].inner is created[0]
        assert context.wrapped[0].server_hostname == "api.example"
        assert created[0].peer == ("api.example", 443)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        conn.close()

    def test_tls_context_pins_tls12_floor_on_the_real_default_context(self, ztna):
        ctx = ztna.tls_context()
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True

    def test_tls_failure_closes_the_socket(self, ztna, monkeypatch):
        created = []
        context = FakeTlsContext(error=ssl.SSLCertVerificationError("certificate verify failed"))

        def fake_create_connection(address, timeout=None):
            sock = FakeSocket()
            created.append(sock)
            return sock

        monkeypatch.setattr(socket, "create_connection", fake_create_connection)
        monkeypatch.setattr(ssl, "create_default_context", lambda: context)
        with pytest.raises(ssl.SSLCertVerificationError):
            ztna.open_upstream_connection(ztna.parse_upstream("https://api.example"), 8.0)
        assert created[0].closed is True
