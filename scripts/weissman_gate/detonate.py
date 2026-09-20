#!/usr/bin/env python3
"""Detonation farm lab — static analysis of a fetched URL.

Never executes the sample unless WEISSMAN_DETONATE_EXEC=1 AND bwrap or firejail
is on PATH. Isolated from fingerprint_engine verification_sandbox (heal).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = int(os.environ.get("WEISSMAN_DETONATION_PORT", "8745"))


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

    def do_GET(self):
        body = json.dumps({"ok": True, "component": "weissman-detonation"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            payload = {}
        url = str(payload.get("url") or "").strip()
        if not url.startswith("http"):
            body = json.dumps({"ok": False, "detail": "url required"}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                blob = resp.read(8_000_000)
        except Exception as e:
            body = json.dumps({"ok": False, "detail": str(e)}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        result = analyze_bytes(blob, url)
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"weissman-detonation http://{HOST}:{PORT}/", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
