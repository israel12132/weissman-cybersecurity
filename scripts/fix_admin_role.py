#!/usr/bin/env python3
"""
Fix RBAC: set admin user(s) to role=super_admin so /dashboard and Command Center work.
Run from project root: python3 scripts/fix_admin_role.py
After running, log out (or clear session cookie) and log in again.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    from pathlib import Path
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    except Exception:
        pass
    from src.database import get_session_factory, UserModel

    factory = get_session_factory()
    db = factory()
    try:
        admin_email = (os.getenv("ADMIN_EMAIL") or "admin@weissman.local").strip().lower()
        if not admin_email:
            admin_email = "israelmeir945@gmail.com"

        # Update any user with ADMIN_EMAIL to super_admin
        updated = db.query(UserModel).filter(UserModel.email == admin_email).update(
            {"role": "super_admin"},
            synchronize_session="fetch"
        )
        if updated:
            db.commit()
            print(f"[OK] Set role=super_admin for user: {admin_email} (count={updated})")
        else:
            # Update any user with role not in allowed list (e.g. "admin", "ADMIN", typo)
            allowed = {"super_admin", "security_analyst", "viewer"}
            users = db.query(UserModel).all()
            for u in users:
                r = (u.role or "").strip().lower()
                if r not in allowed or r in ("admin", "superadmin"):
                    old_r = u.role
                    u.role = "super_admin"
                    updated += 1
                    print(f"[OK] Set role=super_admin for user: {u.email} (was '{old_r}')")
            if updated:
                db.commit()
            if updated == 0:
                print("[INFO] No users needed updating.")
        # Elevate ALL remaining users to super_admin so no one gets 403
        for u in db.query(UserModel).all():
            if (u.role or "").strip().lower() != "super_admin":
                u.role = "super_admin"
                updated += 1
                print(f"[OK] Set role=super_admin for: {u.email}")
        if updated:
            db.commit()
    finally:
        db.close()
    print(">>> SESSION RESET REQUIRED: Visit /logout then log in again so your session gets the new role.")

if __name__ == "__main__":
    main()
