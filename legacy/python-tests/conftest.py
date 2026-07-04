"""
tests/conftest.py
=================
Shared pytest fixtures and configuration for all tests.
"""

import os
import sys
from pathlib import Path

import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables and in-process rate-limiter state before each test."""
    # Save original env
    original_env = dict(os.environ)

    # Clear in-memory rate-limiter sliding windows so tests don't bleed state.
    try:
        from src.rate_limiter import _mem_windows
        _mem_windows.clear()
    except Exception:
        pass

    yield

    # Restore original env
    os.environ.clear()
    os.environ.update(original_env)

    # Clean up again after the test
    try:
        from src.rate_limiter import _mem_windows
        _mem_windows.clear()
    except Exception:
        pass


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    return {
        "title": "SQL Injection in Login Form",
        "description": "The login form is vulnerable to SQL injection attacks",
        "severity": "high",
        "url": "https://example.com/login",
        "proof": "curl -X POST https://example.com/login -d \"username=admin' OR '1'='1\"",
    }


@pytest.fixture
def clean_rate_limiter_state():
    """Clean rate limiter state before each test."""
    from src.rate_limiter import _mem_windows
    from src.redis_client import reset_redis_client

    _mem_windows.clear()
    reset_redis_client()

    yield

    _mem_windows.clear()
    reset_redis_client()
