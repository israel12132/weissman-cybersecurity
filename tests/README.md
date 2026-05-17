# Weissman Cybersecurity Test Suite

Comprehensive test suite for the Weissman Cybersecurity platform.

## Structure

```
tests/
├── unit/              # Fast, isolated unit tests
├── integration/       # Tests with database/external services
├── e2e/              # End-to-end workflow tests
└── conftest.py       # Shared fixtures and configuration
```

## Running Tests

### All tests
```bash
pytest
```

### Specific test file
```bash
pytest tests/unit/test_html_sanitizer.py -v
```

### Tests by marker
```bash
pytest -m unit           # Only unit tests
pytest -m integration    # Only integration tests
pytest -m security       # Security-focused tests
```

### With coverage
```bash
pytest --cov=src --cov-report=html --cov-report=term-missing
```

## Test Requirements

Install test dependencies:
```bash
pip install -r requirements.txt
```

Required packages:
- pytest >= 7.4.0
- pytest-cov >= 4.1.0
- pytest-asyncio >= 0.21.0
- pytest-mock >= 3.11.0

## Writing Tests

### Unit Tests
- Fast (< 1 second per test)
- No external dependencies
- Mock all I/O operations
- Use `@pytest.mark.unit` decorator

Example:
```python
@pytest.mark.unit
def test_sanitise_text():
    output = sanitise_text("<script>alert(1)</script>")
    assert "&lt;script&gt;" in output
```

### Integration Tests
- Test interaction with database, Redis, external APIs
- Use fixtures for setup/teardown
- Use `@pytest.mark.integration` decorator

### E2E Tests
- Test complete user workflows
- May be slow
- Use `@pytest.mark.e2e` decorator

## Coverage Goals

Target coverage by module:
- `src/html_sanitizer.py`: 95%+
- `src/rate_limiter.py`: 90%+
- `src/auth_enterprise.py`: 90%+
- Overall: 80%+

## CI/CD Integration

Tests run automatically on:
- Pull requests
- Commits to main branch
- Nightly builds

Minimum requirements for PR merge:
- All tests pass
- Coverage > 80%
- No security vulnerabilities
