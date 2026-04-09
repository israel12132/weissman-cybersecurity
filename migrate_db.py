#!/usr/bin/env python3
"""
One-time migration: add webhooks.secret column to existing SQLite app.db.
Run from project root: python3 migrate_db.py
Safe to run multiple times (skips if column already exists).
"""
import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "app.db")


def main():
    if not os.path.isfile(DB_PATH):
        print(f"DB not found: {DB_PATH}. No migration needed.")
        return 0
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute("PRAGMA table_info(webhooks)")
        columns = [row[1] for row in cur.fetchall()]
        if "secret" in columns:
            print("webhooks.secret already exists. No migration needed.")
            return 0
        conn.execute("ALTER TABLE webhooks ADD COLUMN secret TEXT DEFAULT ''")
        conn.commit()
        print("Added webhooks.secret column successfully.")
    except Exception as e:
        print(f"Migration failed: {e}", file=sys.stderr)
        conn.rollback()
        return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
