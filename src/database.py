"""
Weissman-cybersecurity Enterprise: PostgreSQL with async SQLAlchemy.
Sync session factory retained for Celery workers; FastAPI uses async sessions.
Production: SQL_ECHO forced False via config to prevent I/O and log leaks.
"""
from datetime import datetime
from pathlib import Path
import json
import os

from sqlalchemy import Column, Integer, String, Text, DateTime, Index, text, Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy import event

Base = declarative_base()

# PostgreSQL URL: async for FastAPI, sync for Celery
def _get_db_url() -> str:
    url = os.getenv("DATABASE_URL", "")
    if url:
        if url.startswith("postgresql://") and "asyncpg" not in url:
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url
    # Fallback SQLite for local dev when POSTGRES not set
    DB_PATH = Path(__file__).resolve().parent.parent / "data" / "app.db"
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{DB_PATH}"

def _get_sync_url() -> str:
    u = os.getenv("DATABASE_URL", "")
    if u and u.startswith("postgresql+"):
        return u.replace("postgresql+asyncpg://", "postgresql://", 1)
    if u:
        return u
    DB_PATH = Path(__file__).resolve().parent.parent / "data" / "app.db"
    return f"sqlite:///{DB_PATH}"

# Async engine for FastAPI (PostgreSQL only when DATABASE_URL is set)
_async_engine = None
_sync_engine = None

# Enterprise: unlimited/massive pool to prevent choking under Tesla/Microsoft/Google-scale load
POSTGRES_POOL_SIZE = 500
POSTGRES_MAX_OVERFLOW = 1000
POSTGRES_POOL_TIMEOUT = 60


def _sql_echo() -> bool:
    """Production: forced False to avoid I/O and log leaks. See config.get_sql_echo."""
    try:
        from src.config import get_sql_echo
        return get_sql_echo()
    except ImportError:
        return (os.getenv("SQL_ECHO") or "").strip().lower() in ("true", "1", "yes")


def get_async_engine():
    """Async engine (PostgreSQL only). Massive pool 500 + 1000 overflow, 60s timeout, pre_ping to recover stale connections."""
    global _async_engine
    if _async_engine is None:
        url = os.getenv("DATABASE_URL", "")
        if url and "postgresql" in url:
            async_url = url.replace("postgresql://", "postgresql+asyncpg://", 1) if "asyncpg" not in url else url
            _async_engine = create_async_engine(
                async_url,
                pool_size=POSTGRES_POOL_SIZE,
                max_overflow=POSTGRES_MAX_OVERFLOW,
                pool_timeout=POSTGRES_POOL_TIMEOUT,
                pool_pre_ping=True,
                echo=_sql_echo(),
            )
        else:
            _async_engine = None
    return _async_engine

def get_engine():
    """
    Sync engine for Celery workers and fallback.
    PostgreSQL: Enterprise pool (100 + 200 overflow) for 200+ concurrent workers.
    SQLite: NullPool + WAL + synchronous=NORMAL + busy_timeout.
    """
    global _sync_engine
    if _sync_engine is None:
        url = _get_sync_url()
        is_sqlite = "sqlite" in url
        connect_args = {} if not is_sqlite else {"check_same_thread": False}
        if is_sqlite:
            _sync_engine = create_engine(
                url,
                poolclass=NullPool,
                connect_args=connect_args,
                echo=_sql_echo(),
            )
        else:
            _sync_engine = create_engine(
                url,
                pool_size=POSTGRES_POOL_SIZE,
                max_overflow=POSTGRES_MAX_OVERFLOW,
                pool_timeout=POSTGRES_POOL_TIMEOUT,
                pool_pre_ping=True,
                connect_args=connect_args,
                echo=_sql_echo(),
            )
        if is_sqlite:
            @event.listens_for(_sync_engine, "connect")
            def _sqlite_pragmas(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.close()
    return _sync_engine


# Multi-tenancy: thousands of corporate accounts (global scale)
class TenantModel(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(64), unique=True, index=True, nullable=False)
    settings_json = Column(Text, default="{}")  # quotas, region preference, etc.
    region = Column(String(64), nullable=True, index=True)  # data sovereignty: EU-West, US-East, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ClientModel(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, nullable=True, index=True)  # FK to tenants; null = default tenant
    name = Column(String(255), nullable=False)
    domains = Column(Text, default="[]")
    ip_ranges = Column(Text, default="[]")
    tech_stack = Column(Text, default="[]")
    auto_detect_tech_stack = Column(Integer, default=1, nullable=False)  # 1=auto-detect (read-only in UI), 0=manual
    contact_email = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_scope_dict(self):
        return {
            "domains": json.loads(self.domains or "[]"),
            "ip_ranges": json.loads(self.ip_ranges or "[]"),
            "tech_stack": json.loads(self.tech_stack or "[]"),
        }


class ReportRunModel(Base):
    __tablename__ = "report_runs"
    __table_args__ = (Index("ix_report_runs_created_at", "created_at"), Index("ix_report_runs_tenant_id", "tenant_id"), Index("ix_report_runs_region", "region"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, nullable=True, index=True)  # data isolation: only tenant's reports
    region = Column(String(64), nullable=True, index=True)  # data sovereignty: where this run was generated
    created_at = Column(DateTime, default=datetime.utcnow)
    findings_json = Column(Text, default="[]")
    summary = Column(Text, default="{}")
    pdf_path = Column(String(1024), nullable=True)  # path under /reports for auto-generated PDF (CompanyName_VulnID_Timestamp.pdf)


class WebhookModel(Base):
    __tablename__ = "webhooks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, nullable=True, index=True)  # null = global (super_admin only)
    url = Column(String(2048), nullable=False)
    enabled = Column(Integer, default=1)
    secret = Column(String(512), default="")  # for HMAC signing
    created_at = Column(DateTime, default=datetime.utcnow)


class AlertSentModel(Base):
    __tablename__ = "alert_sent"
    __table_args__ = (
        Index("ix_alert_sent_alerted_at", "alerted_at"),
        Index("ix_alert_sent_target_finding", "target", "finding_id"),
        Index("ix_alert_sent_target_alerted_at", "target", "alerted_at"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(512), nullable=False, index=True)
    finding_id = Column(String(512), nullable=False, index=True)
    alerted_at = Column(DateTime, default=datetime.utcnow)


# RBAC: User (roles: super_admin, security_analyst, viewer). tenant_id = data isolation.
# SSO: password_hash nullable when sso_provider set; sso_id = IdP subject.
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, nullable=True, index=True)  # null = can access all tenants (super_admin)
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=True)  # nullable for SSO-only users
    role = Column(String(64), nullable=False, default="viewer")  # super_admin, security_analyst, viewer
    mfa_secret = Column(String(64), default="")  # TOTP secret (encrypted in prod)
    mfa_enabled = Column(Boolean, default=False)
    sso_provider = Column(String(64), nullable=True, index=True)  # google, okta, etc.
    sso_id = Column(String(255), nullable=True, index=True)  # IdP subject id
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# API keys for public API (/api/v1). Key hashed in DB; prefix stored for lookup.
class ApiKeyModel(Base):
    __tablename__ = "api_keys"
    __table_args__ = (Index("ix_api_keys_key_hash", "key_hash"), Index("ix_api_keys_tenant_id", "tenant_id"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, nullable=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)  # optional: key tied to user
    name = Column(String(128), nullable=False)  # label e.g. "CI/CD", "Partner X"
    key_prefix = Column(String(16), nullable=False, index=True)  # first 8 chars for lookup
    key_hash = Column(String(128), nullable=False, index=True)  # hashlib.sha256(secret).hexdigest()
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


# Vulnerability lifecycle: one row per finding with status (OPEN, IN_PROGRESS, FIXED, FALSE_POSITIVE).
# Populated when report run is created; PUT /api/findings/{id}/status updates status.
class VulnerabilityModel(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vulnerabilities_run_id", "run_id"),
        Index("ix_vulnerabilities_client_id", "client_id"),
        Index("ix_vulnerabilities_status", "status"),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, nullable=False, index=True)
    tenant_id = Column(Integer, nullable=True, index=True)
    client_id = Column(String(64), nullable=False, index=True)
    finding_id = Column(String(256), nullable=False, index=True)  # CVE id or source id
    title = Column(String(512), default="")
    severity = Column(String(32), default="medium")
    source = Column(String(64), default="")
    description = Column(Text, default="")
    status = Column(String(32), nullable=False, default="OPEN", index=True)  # OPEN, IN_PROGRESS, FIXED, FALSE_POSITIVE
    proof = Column(Text, nullable=True)  # exact HTTP request/response from fuzzer or PoC
    discovered_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SystemAuditLogModel(Base):
    """Immutable audit log: every action logged."""
    __tablename__ = "system_audit_logs"
    __table_args__ = (Index("ix_audit_created_at", "created_at"), Index("ix_audit_user_id", "user_id"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, nullable=True, index=True)
    user_email = Column(String(255), default="")
    action = Column(String(128), nullable=False, index=True)  # login, scan_trigger, report_download, etc.
    ip_address = Column(String(64), default="")
    details = Column(Text, default="{}")  # JSON


class AttackSurfaceSnapshotModel(Base):
    """Delta-scan: last known state per target to detect changes only."""
    __tablename__ = "attack_surface_snapshots"
    __table_args__ = (Index("ix_snapshot_target", "target_id"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(String(128), nullable=False, index=True)  # client id or url
    target_type = Column(String(32), default="client")  # client, domain
    ports_json = Column(Text, default="[]")
    headers_hash = Column(String(64), default="")  # hash of critical headers
    cve_ids_json = Column(Text, default="[]")
    assets_json = Column(Text, default="[]")  # discovered subdomains, IPs, buckets (Shadow IT)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MonitoredSourceModel(Base):
    """Autonomous discovery: hacker forums, leak sites, .onion sources added by the crawler."""
    __tablename__ = "monitored_sources"
    __table_args__ = (Index("ix_monitored_sources_url", "url"), Index("ix_monitored_sources_validated", "validated"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    source_type = Column(String(64), default="onion_forum")
    risk_level = Column(String(32), default="high")
    validated = Column(Boolean, default=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    """Create tables (sync). For PostgreSQL use Alembic in production."""
    import sqlalchemy.exc
    engine = get_engine()
    try:
        Base.metadata.create_all(engine)
    except sqlalchemy.exc.OperationalError as e:
        if "already exists" not in str(e).lower():
            raise
    if "sqlite" in _get_sync_url():
        with engine.connect() as conn:
            try:
                conn.execute(text("ALTER TABLE attack_surface_snapshots ADD COLUMN assets_json TEXT DEFAULT '[]'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE clients ADD COLUMN tenant_id INTEGER"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE webhooks ADD COLUMN secret TEXT DEFAULT ''"))
                conn.commit()
            except Exception:
                pass
            for col, tbl in (
                ("tenant_id", "report_runs"),
                ("tenant_id", "webhooks"),
                ("tenant_id", "users"),
            ):
                try:
                    conn.execute(text(f"ALTER TABLE {tbl} ADD COLUMN {col} INTEGER"))
                    conn.commit()
                except Exception:
                    pass
            for col, tbl in (("region", "tenants"), ("region", "report_runs")):
                try:
                    conn.execute(text(f"ALTER TABLE {tbl} ADD COLUMN {col} TEXT"))
                    conn.commit()
                except Exception:
                    pass
            try:
                conn.execute(text("ALTER TABLE report_runs ADD COLUMN pdf_path VARCHAR(1024)"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN sso_provider VARCHAR(64)"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE users ADD COLUMN sso_id VARCHAR(255)"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN proof TEXT"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE clients ADD COLUMN auto_detect_tech_stack INTEGER DEFAULT 1"))
                conn.commit()
            except Exception:
                pass
            for stmt in (
                "CREATE INDEX IF NOT EXISTS ix_report_runs_created_at ON report_runs(created_at)",
                "CREATE INDEX IF NOT EXISTS ix_alert_sent_alerted_at ON alert_sent(alerted_at)",
                "CREATE INDEX IF NOT EXISTS ix_alert_sent_target_finding ON alert_sent(target, finding_id)",
                "CREATE INDEX IF NOT EXISTS ix_alert_sent_target_alerted_at ON alert_sent(target, alerted_at)",
            ):
                try:
                    conn.execute(text(stmt))
                except Exception:
                    pass
            conn.commit()
    return engine


# Async session for FastAPI
_async_session_factory = None

def get_async_session_factory():
    global _async_session_factory
    if _async_session_factory is None:
        eng = get_async_engine()
        if eng is not None:
            _async_session_factory = async_sessionmaker(
                eng, class_=AsyncSession, expire_on_commit=False, autoflush=False
            )
    return _async_session_factory

async def get_async_session():
    factory = get_async_session_factory()
    if factory is None:
        return
    async with factory() as session:
        yield session


# Sync session for Celery and fallback
_session_factory = None

def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _session_factory

def get_db() -> Session:
    global _session_factory
    if _session_factory is None:
        _session_factory = get_session_factory()
    return _session_factory()
