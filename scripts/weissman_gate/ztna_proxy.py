#!/usr/bin/env python3
"""Identity-aware reverse proxy lab (ZTNA/SWG starter).

Requires Authorization: Bearer <token> matching WEISSMAN_ZTNA_TOKEN.
Forwards to WEISSMAN_ZTNA_UPSTREAM. Fails closed if token unset.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = int(os.environ.get("WEISSMAN_ZTNA_PORT", "8744"))
UPSTREAM = os.environ.get("WEISSMAN_ZTNA_UPSTREAM", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("WEISSMAN_ZTNA_TOKEN", "").strip()


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
        if auth != f"Bearer {TOKEN}":
            return self._deny(401, "missing or invalid bearer token")
        url = UPSTREAM + self.path
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/octet-stream"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._deny(502, str(e))

    def do_POST(self):
        self._deny(405, "POST not enabled on lab ZTNA proxy")


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"weissman-ztna http://{HOST}:{PORT}/ -> {UPSTREAM}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
