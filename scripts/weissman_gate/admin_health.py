#!/usr/bin/env python3
"""Weissman Gate lab admin — live health only. Bind 127.0.0.1."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8743


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        body = json.dumps(
            {
                "ok": True,
                "component": "weissman-gate",
                "dataplane": "admin",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"weissman-gate admin http://{HOST}:{PORT}/", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
