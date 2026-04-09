#!/usr/bin/env python3
"""Create an API key for the Public API (X-API-Key). Key is hashed in DB; plain key printed once."""
import hashlib
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

from src.database import get_session_factory, ApiKeyModel


def _hash_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def main():
    name = os.getenv("API_KEY_NAME", "Default")
    tenant_id = os.getenv("API_KEY_TENANT_ID", "")
    tenant_id = int(tenant_id) if tenant_id.isdigit() else None
    key_secret = secrets.token_urlsafe(32)
    key_prefix = key_secret[:8]
    key_hash = _hash_key(key_secret)
    factory = get_session_factory()
    db = factory()
    try:
        rec = ApiKeyModel(
            tenant_id=tenant_id,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
        )
        db.add(rec)
        db.commit()
        print("API key created. Use this value once (it will not be shown again):")
        print(key_secret)
        print("\nHeader: X-API-Key: <above value>")
    finally:
        db.close()


if __name__ == "__main__":
    main()
