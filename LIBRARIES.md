# Weissman-cybersecurity — Libraries (Latest Stable, No Conflicts)

All dependencies use **latest stable, mutually compatible** versions. One known conflict is resolved: **bcrypt** is pinned to `<5.0.0` because passlib is not yet compatible with bcrypt 5.x.

## Install (single command — installs everything and verifies)

```bash
cd /home/israel/Desktop/security-assessment-bot && ./install_deps.sh
```

Or manually:

```bash
cd /home/israel/Desktop/security-assessment-bot
source venv/bin/activate
pip install -r requirements.txt --upgrade
pip check
```

## Core stack (versions in use)

| Package | Min version | Purpose |
|--------|-------------|---------|
| **fastapi** | 0.135.1 | Web API |
| **uvicorn[standard]** | 0.41.0 | ASGI server (with uvloop, httptools) |
| **starlette** | 0.52.1 | ASGI toolkit |
| **sqlalchemy** | 2.0.48 | ORM, async support |
| **celery[redis]** | 5.6.2 | Task queue |
| **redis** | 7.2+ | Broker & cache |
| **pydantic** | 2.12+ | Validation & settings |
| **requests** | 2.32.5 | HTTP client |
| **tenacity** | 9.1+ | Retries & backoff |
| **aiohttp** | 3.13+ | Async HTTP |
| **weasyprint** | 68.1 | PDF reports |
| **openpyxl** | 3.1.5 | Excel export |
| **pyotp** | 2.9 | MFA (TOTP) |
| **passlib[bcrypt]** | 1.7.4 | Password hashing |
| **authlib** | 1.6+ | OIDC/OAuth2 (SSO) |
| **slowapi** | 0.1.9 | Rate limiting |
| **alembic** | 1.18+ | DB migrations |
| **beautifulsoup4** | 4.14+ | HTML parsing |
| **gunicorn** | 25+ | Production ASGI |

All other packages (jinja2, python-dotenv, pyyaml, markdown, itsdangerous, apscheduler, rich, etc.) are listed in `requirements.txt` with their minimum versions. Run `pip list` after install to see exact versions.

## Resolved conflicts

| Conflict | Resolution |
|----------|------------|
| **passlib** vs **bcrypt 5.x** | passlib is not compatible with bcrypt 5.0+. We pin `bcrypt>=3.1.0,<5.0.0` in `requirements.txt` so passlib[bcrypt] keeps working. |

All other packages are resolved by pip; `pip check` must report "No broken requirements found" after install.

## No mock / dev-only deps

Only production and runtime dependencies are in `requirements.txt`. Test frameworks (pytest, etc.) are not required for running the bot.
