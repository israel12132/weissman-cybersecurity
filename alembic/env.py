"""
Alembic env for Weissman-cybersecurity. Uses DATABASE_URL (PostgreSQL).
"""
import os
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy import create_engine
from alembic import context

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def get_url():
    url = os.getenv("DATABASE_URL", "postgresql://weissman:weissman@localhost:5432/weissman")
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgresql://", 1)
    return url

def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    connectable = create_engine(get_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

def _legacy_alembic_allowed() -> bool:
    return os.environ.get("WEISSMAN_ALLOW_LEGACY_ALEMBIC", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# DEPRECATED PATH GUARD. The live schema is owned by the Rust sqlx migrations in
# fingerprint_engine/migrations/ (mirrored to crates/weissman-db/migrations/). These
# Alembic revisions describe the OLD Python SQLAlchemy schema and will DIVERGE/CORRUPT
# a sqlx-managed database. env.py reads the same DATABASE_URL as production, so a stray
# `alembic upgrade head` could hit the live DB — refuse unless explicitly acknowledged.
if not _legacy_alembic_allowed():
    raise SystemExit(
        "Refusing to run DEPRECATED Alembic migrations.\n"
        "Schema is managed by the Rust sqlx migrations in fingerprint_engine/migrations/.\n"
        "Set WEISSMAN_ALLOW_LEGACY_ALEMBIC=1 only if you truly need the legacy Python "
        "schema. See alembic/README.md."
    )

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
