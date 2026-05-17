"""
Weissman-cybersecurity Enterprise: RBAC + MFA (TOTP).
Roles: super_admin, security_analyst, viewer.
MFA mandatory for all roles (pyotp, Google Authenticator compatible).
"""
import os
import re
import secrets
from typing import Annotated

import pyotp
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.database import get_session_factory, UserModel
from src.exceptions import InvalidPasswordError, InsufficientRoleError, AuthenticationError

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_HIERARCHY = {"super_admin": 3, "security_analyst": 2, "viewer": 1}


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength according to security policy.

    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*)

    Parameters
    ----------
    password : str
        The password to validate

    Returns
    -------
    tuple[bool, str]
        (is_valid, error_message or "OK")
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, "OK"


def hash_password(password: str) -> str:
    """Hash password using bcrypt. Validates password strength first."""
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        raise InvalidPasswordError(error_msg, password_length=len(password))
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
        # Reject users with no recognised role (e.g. partially-constructed objects
        # or test mocks that were not assigned a valid role string).
        if not hasattr(user, "role") or user.role not in ROLE_HIERARCHY:
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
