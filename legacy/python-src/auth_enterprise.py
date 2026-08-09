"""
Weissman-cybersecurity Enterprise: Password validation + MFA (TOTP).
Roles: super_admin, security_analyst, viewer.
MFA mandatory for all roles (pyotp, Google Authenticator compatible).

NOTE: This module provides password validation and hashing utilities.
      Authentication and authorization are now handled by the Rust backend (weissman-server).
      The FastAPI-specific require_role() dependency has been removed.
"""
import os
import re

import pyotp
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.database import UserModel
from src.exceptions import InvalidPasswordError

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


def check_role_hierarchy(user_role: str, required_role: str) -> bool:
    """
    Check if user_role meets or exceeds required_role based on hierarchy.

    Parameters
    ----------
    user_role : str
        The role of the user
    required_role : str
        The minimum required role

    Returns
    -------
    bool
        True if user_role >= required_role in hierarchy

    Note
    ----
    Role-based access control is now enforced by the Rust backend.
    This function is a utility for any Python scripts that need to check roles.
    """
    u_level = ROLE_HIERARCHY.get(user_role, 0)
    r_level = ROLE_HIERARCHY.get(required_role, 0)
    return u_level >= r_level


def ensure_user_exists(db: Session) -> None:
    """Create default admin if no users exist (email/password from env)."""
    if db.query(UserModel).count() > 0:
        return
    email = (os.getenv("ADMIN_EMAIL") or "admin@weissman.local").strip().lower()
    password = os.getenv("ADMIN_PASSWORD")
    if not password:
        from src.config import is_production
        if is_production():
            # Never plant a repo-published default password / MFA-off admin in production.
            raise RuntimeError(
                "ADMIN_PASSWORD must be set in production; refusing to seed a default admin"
            )
        password = "ChangeMe123!"
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
