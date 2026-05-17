"""
tests/unit/test_auth_enterprise.py
===================================
Unit tests for authentication and authorization module.

Run with: pytest tests/unit/test_auth_enterprise.py -v
"""

import pytest
from unittest.mock import Mock, MagicMock
from fastapi import Request, HTTPException

from src.auth_enterprise import (
    validate_password,
    hash_password,
    verify_password,
    require_role,
    ROLE_HIERARCHY,
)
from src.exceptions import InvalidPasswordError, InsufficientRoleError


class TestValidatePassword:
    """Tests for password validation policy."""

    def test_accepts_strong_password(self):
        """Should accept password meeting all requirements."""
        password = "MySecureP@ss123"
        is_valid, msg = validate_password(password)
        assert is_valid is True
        assert msg == "OK"

    def test_rejects_too_short(self):
        """Should reject password shorter than 12 characters."""
        password = "Short1!Aa"  # 9 chars
        is_valid, msg = validate_password(password)
        assert is_valid is False
        assert "12 characters" in msg

    def test_rejects_no_uppercase(self):
        """Should reject password without uppercase letter."""
        password = "lowercaseonly123!"
        is_valid, msg = validate_password(password)
        assert is_valid is False
        assert "uppercase" in msg.lower()

    def test_rejects_no_lowercase(self):
        """Should reject password without lowercase letter."""
        password = "UPPERCASEONLY123!"
        is_valid, msg = validate_password(password)
        assert is_valid is False
        assert "lowercase" in msg.lower()

    def test_rejects_no_digit(self):
        """Should reject password without digit."""
        password = "NoDigitsHere!@#"
        is_valid, msg = validate_password(password)
        assert is_valid is False
        assert "digit" in msg.lower()

    def test_rejects_no_special_char(self):
        """Should reject password without special character."""
        password = "NoSpecialChars123Abc"
        is_valid, msg = validate_password(password)
        assert is_valid is False
        assert "special" in msg.lower()

    def test_accepts_various_special_chars(self):
        """Should accept different special characters."""
        special_chars = "!@#$%^&*(),.?\":{}|<>"
        for char in special_chars:
            password = f"ValidPass123{char}"
            is_valid, msg = validate_password(password)
            assert is_valid is True, f"Failed for special char: {char}"

    def test_exactly_12_chars_valid(self):
        """Should accept password exactly 12 characters."""
        password = "ValidPass1!A"  # exactly 12
        is_valid, msg = validate_password(password)
        assert is_valid is True

    def test_very_long_password_valid(self):
        """Should accept very long passwords."""
        password = "V" + "a" * 100 + "1!B"
        is_valid, msg = validate_password(password)
        assert is_valid is True


class TestHashPassword:
    """Tests for password hashing."""

    def test_hashes_valid_password(self):
        """Should hash valid password."""
        password = "SecurePass123!"
        hashed = hash_password(password)

        assert hashed != password
        assert hashed.startswith("$2b$")  # bcrypt prefix
        assert len(hashed) == 60  # bcrypt hash length

    def test_raises_on_weak_password(self):
        """Should raise InvalidPasswordError for weak password."""
        password = "weak"

        with pytest.raises(InvalidPasswordError) as exc_info:
            hash_password(password)

        assert "12 characters" in str(exc_info.value)
        assert exc_info.value.context.get("password_length") == 4

    def test_different_hashes_for_same_password(self):
        """Should produce different hashes for same password (salt)."""
        password = "SecurePass123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2  # Different due to salt

    def test_validates_all_requirements_before_hashing(self):
        """Should validate all password requirements."""
        weak_passwords = [
            "short1!",  # too short
            "nouppercase123!",  # no uppercase
            "NOLOWERCASE123!",  # no lowercase
            "NoDigitsHere!",  # no digit
            "NoSpecialChars123",  # no special char
        ]

        for password in weak_passwords:
            with pytest.raises(InvalidPasswordError):
                hash_password(password)


class TestVerifyPassword:
    """Tests for password verification."""

    def test_verifies_correct_password(self):
        """Should return True for correct password."""
        password = "SecurePass123!"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_rejects_incorrect_password(self):
        """Should return False for incorrect password."""
        password = "SecurePass123!"
        wrong_password = "WrongPass456!"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) is False

    def test_case_sensitive(self):
        """Should be case-sensitive."""
        password = "SecurePass123!"
        hashed = hash_password(password)

        assert verify_password("securepass123!", hashed) is False
        assert verify_password("SECUREPASS123!", hashed) is False

    def test_rejects_similar_password(self):
        """Should reject similar but not identical password."""
        password = "SecurePass123!"
        hashed = hash_password(password)

        similar = "SecurePass123"  # missing !
        assert verify_password(similar, hashed) is False


class TestRequireRole:
    """Tests for role-based access control."""

    def test_allows_matching_role(self):
        """Should allow user with exact role."""
        mock_request = Mock(spec=Request)
        mock_user = Mock()
        mock_user.role = "security_analyst"
        mock_request.state.user = mock_user

        dependency = require_role("security_analyst")
        result = dependency(mock_request)

        assert result == mock_user

    def test_allows_higher_role(self):
        """Should allow user with higher role."""
        mock_request = Mock(spec=Request)
        mock_user = Mock()
        mock_user.role = "super_admin"
        mock_request.state.user = mock_user

        # super_admin should have access to security_analyst endpoints
        dependency = require_role("security_analyst")
        result = dependency(mock_request)

        assert result == mock_user

    def test_blocks_lower_role(self):
        """Should block user with lower role."""
        mock_request = Mock(spec=Request)
        mock_user = Mock()
        mock_user.role = "viewer"
        mock_request.state.user = mock_user

        dependency = require_role("security_analyst")

        with pytest.raises(HTTPException) as exc_info:
            dependency(mock_request)

        assert exc_info.value.status_code == 403
        assert "Insufficient role" in exc_info.value.detail

    def test_blocks_unauthenticated_user(self):
        """Should block request with no authenticated user."""
        mock_request = Mock(spec=Request)
        mock_request.state.user = None

        dependency = require_role("viewer")

        with pytest.raises(HTTPException) as exc_info:
            dependency(mock_request)

        assert exc_info.value.status_code == 401
        assert "Not authenticated" in exc_info.value.detail

    def test_blocks_missing_user_attribute(self):
        """Should block when user attribute doesn't exist."""
        mock_request = Mock(spec=Request)
        # Don't set request.state.user at all

        dependency = require_role("viewer")

        with pytest.raises(HTTPException) as exc_info:
            dependency(mock_request)

        assert exc_info.value.status_code == 401

    def test_role_hierarchy_order(self):
        """Should enforce correct role hierarchy."""
        assert ROLE_HIERARCHY["super_admin"] > ROLE_HIERARCHY["security_analyst"]
        assert ROLE_HIERARCHY["security_analyst"] > ROLE_HIERARCHY["viewer"]


class TestRoleHierarchy:
    """Tests for role hierarchy values."""

    def test_super_admin_highest(self):
        """Super admin should have highest privilege level."""
        assert ROLE_HIERARCHY["super_admin"] == 3

    def test_security_analyst_middle(self):
        """Security analyst should be middle level."""
        assert ROLE_HIERARCHY["security_analyst"] == 2

    def test_viewer_lowest(self):
        """Viewer should have lowest privilege level."""
        assert ROLE_HIERARCHY["viewer"] == 1

    def test_all_roles_defined(self):
        """Should have all three roles defined."""
        assert len(ROLE_HIERARCHY) == 3
        assert "super_admin" in ROLE_HIERARCHY
        assert "security_analyst" in ROLE_HIERARCHY
        assert "viewer" in ROLE_HIERARCHY


class TestPasswordPolicyEdgeCases:
    """Edge cases for password policy."""

    def test_unicode_characters(self):
        """Should handle Unicode characters."""
        password = "Pásswørd123!מבחן"
        is_valid, msg = validate_password(password)
        assert is_valid is True

    def test_whitespace_in_password(self):
        """Should allow whitespace in password."""
        password = "My Secure Pass123!"
        is_valid, msg = validate_password(password)
        assert is_valid is True

    def test_multiple_special_chars(self):
        """Should accept multiple special characters."""
        password = "P@$$w0rd!#2023"
        is_valid, msg = validate_password(password)
        assert is_valid is True

    def test_all_requirements_minimal(self):
        """Should accept password with minimal requirements."""
        password = "Aa1!xxxxxxxx"  # 12 chars, has all requirements
        is_valid, msg = validate_password(password)
        assert is_valid is True


class TestAuthenticationIntegration:
    """Integration tests for authentication flow."""

    def test_full_registration_login_flow(self):
        """Should handle registration and login."""
        # Registration
        password = "UserPass123!"
        hashed = hash_password(password)

        # Verify hash was created
        assert hashed is not None
        assert hashed != password

        # Login attempt with correct password
        assert verify_password(password, hashed) is True

        # Login attempt with wrong password
        assert verify_password("WrongPass123!", hashed) is False

    def test_role_escalation_prevention(self):
        """Should prevent role escalation."""
        mock_request = Mock(spec=Request)
        mock_user = Mock()
        mock_user.role = "viewer"
        mock_request.state.user = mock_user

        # Viewer tries to access admin endpoint
        admin_only = require_role("super_admin")

        with pytest.raises(HTTPException) as exc_info:
            admin_only(mock_request)

        assert exc_info.value.status_code == 403
