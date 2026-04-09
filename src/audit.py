"""
Weissman-cybersecurity Enterprise: immutable audit logging.
Every action (login, scan_trigger, report_download) logged with timestamp, IP, user_id, details.
"""
import json
import logging
from typing import Any

from src.database import get_session_factory, SystemAuditLogModel

logger = logging.getLogger(__name__)


def log_action(
    action: str,
    user_id: int | None = None,
    user_email: str = "",
    ip_address: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    """Append to system_audit_logs. Never raises."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            row = SystemAuditLogModel(
                action=action,
                user_id=user_id,
                user_email=user_email or "",
                ip_address=ip_address or "",
                details=json.dumps(details or {}, default=str),
            )
            db.add(row)
            db.commit()
        finally:
            db.close()
        try:
            from src.events_pub import publish_command_center_event
            publish_command_center_event("audit", {
                "action": action,
                "user_email": user_email or "",
                "details": details or {},
            })
        except Exception:
            pass
    except Exception as e:
        logger.warning("Audit log failed: %s", e)
