"""
src/siem_integration.py
=======================
SIEM integration for centralized logging and security event correlation.

Supports:
- Elasticsearch/ELK Stack
- Splunk
- Structured logging (JSON)
- Security event categorization

Usage:
    from src.siem_integration import log_security_event, configure_siem

    configure_siem(backend="elasticsearch")

    log_security_event(
        event_type="authentication_failure",
        severity="warning",
        user="user@example.com",
        source_ip="192.168.1.100",
        details={"reason": "invalid_password"},
    )
"""

import json
import logging
import os
import socket
from datetime import datetime
from typing import Dict, Any, Optional, Literal

logger = logging.getLogger("weissman.siem")

# SIEM configuration
SIEM_BACKEND = os.getenv("SIEM_BACKEND", "elasticsearch")  # "elasticsearch", "splunk", or "file"
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
SIEM_LOG_PATH = os.getenv("SIEM_LOG_PATH", "/var/log/weissman/security-events.log")

# Event categories for SIEM
EVENT_CATEGORIES = {
    "authentication": ["login", "logout", "mfa_verification", "token_refresh"],
    "authorization": ["access_denied", "permission_check", "role_change"],
    "data_access": ["data_read", "data_write", "data_delete", "export"],
    "security": ["scan_trigger", "finding_detected", "rate_limit_exceeded"],
    "admin": ["user_created", "user_deleted", "settings_changed"],
    "system": ["startup", "shutdown", "error", "health_check"],
}

# Lazy-init clients
_elasticsearch_client: Optional[Any] = None
_splunk_client: Optional[Any] = None


def _get_elasticsearch_client():
    """Lazy initialization of Elasticsearch client."""
    global _elasticsearch_client

    if _elasticsearch_client is not None:
        return _elasticsearch_client

    try:
        from elasticsearch import Elasticsearch

        _elasticsearch_client = Elasticsearch([ELASTICSEARCH_URL])
        logger.info("siem: Elasticsearch client initialized")
        return _elasticsearch_client

    except ImportError:
        logger.warning("siem: elasticsearch library not installed")
        return None
    except Exception as exc:
        logger.warning("siem: Elasticsearch initialization failed (%s)", exc)
        return None


def _get_splunk_client():
    """Lazy initialization of Splunk HEC client."""
    global _splunk_client

    if _splunk_client is not None:
        return _splunk_client

    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return None

    try:
        import requests

        _splunk_client = {
            "url": SPLUNK_HEC_URL,
            "token": SPLUNK_HEC_TOKEN,
            "session": requests.Session(),
        }
        _splunk_client["session"].headers.update({
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        })

        logger.info("siem: Splunk HEC client initialized")
        return _splunk_client

    except Exception as exc:
        logger.warning("siem: Splunk initialization failed (%s)", exc)
        return None


def log_security_event(
    event_type: str,
    severity: Literal["critical", "high", "medium", "low", "info"],
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    **kwargs,
):
    """
    Log structured security event to SIEM.

    Parameters
    ----------
    event_type : str
        Event type (e.g., "authentication_failure", "scan_trigger")
    severity : str
        Event severity level
    user : str, optional
        User identifier
    source_ip : str, optional
        Source IP address
    details : dict, optional
        Additional event details
    **kwargs
        Additional fields

    Examples
    --------
    >>> log_security_event(
    ...     event_type="authentication_failure",
    ...     severity="warning",
    ...     user="attacker@evil.com",
    ...     source_ip="1.2.3.4",
    ...     details={"attempts": 5},
    ... )
    """
    # Build structured event
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "severity": severity,
        "hostname": socket.gethostname(),
        "application": "weissman-cybersecurity",
        "version": "1.0.0",
    }

    # Add optional fields
    if user:
        event["user"] = user
    if source_ip:
        event["source_ip"] = source_ip
    if details:
        event["details"] = details

    # Add any additional kwargs
    event.update(kwargs)

    # Categorize event
    event["category"] = _categorize_event(event_type)

    # Send to configured backend
    if SIEM_BACKEND == "elasticsearch":
        _send_to_elasticsearch(event)
    elif SIEM_BACKEND == "splunk":
        _send_to_splunk(event)
    else:
        _write_to_file(event)


def _categorize_event(event_type: str) -> str:
    """Categorize event type."""
    for category, event_types in EVENT_CATEGORIES.items():
        if any(et in event_type for et in event_types):
            return category
    return "other"


def _send_to_elasticsearch(event: Dict[str, Any]):
    """Send event to Elasticsearch."""
    client = _get_elasticsearch_client()

    if client is None:
        _write_to_file(event)
        return

    try:
        index_name = f"weissman-security-{datetime.utcnow().strftime('%Y.%m')}"

        client.index(
            index=index_name,
            document=event,
        )

        logger.debug("siem: sent event to Elasticsearch index %s", index_name)

    except Exception as exc:
        logger.error("siem: failed to send to Elasticsearch (%s)", exc)
        _write_to_file(event)


def _send_to_splunk(event: Dict[str, Any]):
    """Send event to Splunk HEC."""
    client = _get_splunk_client()

    if client is None:
        _write_to_file(event)
        return

    try:
        payload = {
            "time": event["timestamp"],
            "event": event,
            "sourcetype": "_json",
            "source": "weissman-cybersecurity",
        }

        response = client["session"].post(
            client["url"],
            json=payload,
            verify=False,
        )

        if response.status_code != 200:
            logger.warning("siem: Splunk HEC returned status %d", response.status_code)

        logger.debug("siem: sent event to Splunk HEC")

    except Exception as exc:
        logger.error("siem: failed to send to Splunk (%s)", exc)
        _write_to_file(event)


def _write_to_file(event: Dict[str, Any]):
    """Write event to JSON log file."""
    try:
        os.makedirs(os.path.dirname(SIEM_LOG_PATH), exist_ok=True)

        with open(SIEM_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")

        logger.debug("siem: wrote event to file %s", SIEM_LOG_PATH)

    except Exception as exc:
        logger.error("siem: failed to write to file (%s)", exc)


def configure_siem(
    backend: Literal["elasticsearch", "splunk", "file"] = "elasticsearch",
    **config,
):
    """
    Configure SIEM integration.

    Parameters
    ----------
    backend : str
        SIEM backend type
    **config
        Backend-specific configuration

    Examples
    --------
    >>> configure_siem(backend="elasticsearch", url="http://es:9200")
    >>> configure_siem(backend="splunk", hec_url="https://splunk:8088", token="...")
    """
    global SIEM_BACKEND, ELASTICSEARCH_URL, SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN

    SIEM_BACKEND = backend

    if backend == "elasticsearch" and "url" in config:
        ELASTICSEARCH_URL = config["url"]
        global _elasticsearch_client
        _elasticsearch_client = None  # Force re-init

    elif backend == "splunk":
        if "hec_url" in config:
            SPLUNK_HEC_URL = config["hec_url"]
        if "token" in config:
            SPLUNK_HEC_TOKEN = config["token"]
        global _splunk_client
        _splunk_client = None  # Force re-init

    logger.info("siem: configured backend=%s", backend)


# Convenience functions for common events
def log_authentication_event(
    success: bool,
    user: str,
    source_ip: str,
    method: str = "password",
    **kwargs,
):
    """Log authentication attempt."""
    log_security_event(
        event_type="authentication_success" if success else "authentication_failure",
        severity="info" if success else "warning",
        user=user,
        source_ip=source_ip,
        details={"method": method, **kwargs},
    )


def log_authorization_event(
    granted: bool,
    user: str,
    resource: str,
    action: str,
    **kwargs,
):
    """Log authorization check."""
    log_security_event(
        event_type="authorization_granted" if granted else "authorization_denied",
        severity="info" if granted else "warning",
        user=user,
        details={"resource": resource, "action": action, **kwargs},
    )


def log_scan_event(
    scan_id: str,
    target: str,
    user: str,
    findings_count: int = 0,
    **kwargs,
):
    """Log security scan event."""
    log_security_event(
        event_type="scan_completed",
        severity="info",
        user=user,
        details={
            "scan_id": scan_id,
            "target": target,
            "findings_count": findings_count,
            **kwargs,
        },
    )


def log_rate_limit_event(
    identity: str,
    key_prefix: str,
    limit: int,
    source_ip: Optional[str] = None,
):
    """Log rate limit violation."""
    log_security_event(
        event_type="rate_limit_exceeded",
        severity="warning",
        user=identity,
        source_ip=source_ip,
        details={"key_prefix": key_prefix, "limit": limit},
    )


def log_data_access_event(
    user: str,
    action: Literal["read", "write", "delete", "export"],
    resource: str,
    **kwargs,
):
    """Log data access event."""
    log_security_event(
        event_type=f"data_{action}",
        severity="info" if action == "read" else "medium",
        user=user,
        details={"resource": resource, **kwargs},
    )


def query_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    user: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100,
) -> list[Dict[str, Any]]:
    """
    Query security events from SIEM.

    Parameters
    ----------
    event_type : str, optional
        Filter by event type
    severity : str, optional
        Filter by severity
    user : str, optional
        Filter by user
    start_time : datetime, optional
        Start of time range
    end_time : datetime, optional
        End of time range
    limit : int
        Maximum results to return

    Returns
    -------
    list[dict]
        Matching events

    Examples
    --------
    >>> events = query_events(
    ...     event_type="authentication_failure",
    ...     severity="warning",
    ...     limit=50,
    ... )
    """
    if SIEM_BACKEND == "elasticsearch":
        return _query_elasticsearch(event_type, severity, user, start_time, end_time, limit)
    else:
        return _query_file(event_type, severity, user, start_time, end_time, limit)


def _query_elasticsearch(
    event_type: Optional[str],
    severity: Optional[str],
    user: Optional[str],
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    limit: int,
) -> list[Dict[str, Any]]:
    """Query Elasticsearch for events."""
    client = _get_elasticsearch_client()

    if client is None:
        return []

    try:
        # Build query
        must = []
        if event_type:
            must.append({"match": {"event_type": event_type}})
        if severity:
            must.append({"match": {"severity": severity}})
        if user:
            must.append({"match": {"user": user}})

        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time.isoformat()
            if end_time:
                time_range["lte"] = end_time.isoformat()
            must.append({"range": {"timestamp": time_range}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        # Search
        response = client.search(
            index="weissman-security-*",
            body=query,
        )

        events = [hit["_source"] for hit in response["hits"]["hits"]]
        return events

    except Exception as exc:
        logger.error("siem: query failed (%s)", exc)
        return []


def _query_file(
    event_type: Optional[str],
    severity: Optional[str],
    user: Optional[str],
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    limit: int,
) -> list[Dict[str, Any]]:
    """Query file-based logs."""
    if not os.path.exists(SIEM_LOG_PATH):
        return []

    events = []

    try:
        with open(SIEM_LOG_PATH, "r") as f:
            for line in f:
                event = json.loads(line)

                # Apply filters
                if event_type and event.get("event_type") != event_type:
                    continue
                if severity and event.get("severity") != severity:
                    continue
                if user and event.get("user") != user:
                    continue

                # Time range filtering
                if start_time or end_time:
                    ts_raw = event.get("timestamp")
                    if ts_raw:
                        try:
                            if isinstance(ts_raw, str):
                                event_ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                            else:
                                event_ts = datetime.fromtimestamp(float(ts_raw))
                            if start_time and event_ts < start_time:
                                continue
                            if end_time and event_ts > end_time:
                                continue
                        except (ValueError, TypeError, OSError):
                            pass

                events.append(event)

                if len(events) >= limit:
                    break

        return events

    except Exception as exc:
        logger.error("siem: file query failed (%s)", exc)
        return []
