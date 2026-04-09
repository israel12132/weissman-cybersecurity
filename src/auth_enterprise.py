"""
Weissman-cybersecurity Enterprise: RBAC + MFA (TOTP).
Roles: super_admin, security_analyst, viewer.
MFA mandatory for all roles (pyotp, Google Authenticator compatible).
"""
import os
import secrets
from typing import Annotated

import pyotp
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.database import get_session_factory, UserModel

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_HIERARCHY = {"super_admin": 3, "security_analyst": 2, "viewer": 1}


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def get_user_by_email(db: Session, email: str) -> UserModel | None:
    return db.query(UserModel).filter(UserModel.email == email.strip().lower()).first()


def require_role(min_role: str):
    """Dependency: require at least min_role (super_admin > security_analyst > viewer)."""
    def _inner(request: Request):
        user = getattr(request.state, "user", None)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        u_level = ROLE_HIERARCHY.get(user.role, 0)
        r_level = ROLE_HIERARCHY.get(min_role, 0)
        if u_level < r_level:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return _inner


def ensure_user_exists(db: Session) -> None:
    """Create default admin if no users exist (email/password from env)."""
    if db.query(UserModel).count() > 0:
        return
    email = (os.getenv("ADMIN_EMAIL") or "admin@weissman.local").strip().lower()
    password = os.getenv("ADMIN_PASSWORD") or "ChangeMe123!"
    secret = pyotp.random_base32()
    user = UserModel(
        email=email,
        password_hash=hash_password(password),
        role="super_admin",
        mfa_secret=secret,
        mfa_enabled=False,  # first login must set MFA
    )
    db.add(user)
    db.commit()
