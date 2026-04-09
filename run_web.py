#!/usr/bin/env python3
"""Deprecated: the FastAPI/Celery stack was removed. Use the Rust production server."""

import sys

def main() -> None:
    print(
        "The Python web server (src.web.app) and Celery workers have been removed.\n"
        "Use the unified Rust entrypoint:\n"
        "  cargo run -p weissman-server\n"
        "  nix run .#default\n",
        file=sys.stderr,
    )
    sys.exit(2)

if __name__ == "__main__":
    main()
