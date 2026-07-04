"""Load and validate configuration. Production security: SQL_ECHO forced False, SECRET_KEY validated."""
from pathlib import Path
from typing import Optional

import os
import logging
import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def is_production() -> bool:
    """True when WEISSMAN_ENV=production or PRODUCTION=1 (avoids SQL echo and enables strict checks)."""
    env = (os.getenv("WEISSMAN_ENV") or os.getenv("ENV") or "").strip().lower()
    if env == "production" or env == "prod":
        return True
    if (os.getenv("PRODUCTION") or "").strip() in ("1", "true", "yes"):
        return True
    return False


def get_sql_echo() -> bool:
    """SQL_ECHO is forced False in production to prevent I/O bottlenecks and log data leaks."""
    if is_production():
        return False
    return (os.getenv("SQL_ECHO") or "").strip().lower() in ("true", "1", "yes")


def get_secret_key() -> str:
    """SECRET_KEY from env. In production, warn if default/empty."""
    key = (os.getenv("SECRET_KEY") or os.getenv("WEISSMAN_SECRET_KEY") or "").strip()
    if is_production() and (not key or key in ("change-me-in-production", "change-me", "secret")):
        logger.warning("SECRET_KEY is default or empty in production. Set SECRET_KEY in .env.")
    return key or "change-me-in-production"


class Scope(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)


class Client(BaseModel):
    id: str
    name: str
    scope: Scope
    contact_email: Optional[str] = None


class NVDConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""


class GitHubConfig(BaseModel):
    enabled: bool = True
    token: str = ""


class OSVConfig(BaseModel):
    enabled: bool = True


class OTXConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""


class HIBPConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""


class IntelligenceConfig(BaseModel):
    nvd: NVDConfig = Field(default_factory=NVDConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    osv: OSVConfig = Field(default_factory=OSVConfig)
    otx: OTXConfig = Field(default_factory=OTXConfig)
    hibp: HIBPConfig = Field(default_factory=HIBPConfig)


class ReportingConfig(BaseModel):
    hourly: bool = True
    output_dir: str = "./reports"
    format: list[str] = Field(default_factory=lambda: ["html", "json"])
    timezone: str = "Asia/Jerusalem"


class SchedulerConfig(BaseModel):
    check_interval_hours: int = 1
    feed_refresh_minutes: int = 15


class Config(BaseModel):
    clients: list[Client] = Field(default_factory=list)
    intelligence: IntelligenceConfig = Field(default_factory=IntelligenceConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)


def load_config(path: str | Path = "config.yaml") -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {p}. Copy config.example.yaml to config.yaml")
    data = yaml.safe_load(p.read_text())
    return Config.model_validate(data)
