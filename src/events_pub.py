"""
Weissman-cybersecurity: Publish real-time events to Command Center via Redis PubSub.
Celery/workers and API call publish_event(); WebSocket subscribers receive instantly.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

REDIS_CC_CHANNEL = "weissman:cc:events"


def publish_command_center_event(kind: str, payload: dict[str, Any]) -> None:
    """
    Publish one event to Redis channel for WebSocket broadcast.
    kind: audit | scan_pulse | darkweb | critical_cve | fuzzer_anomaly
    """
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        return
    try:
        import redis
        r = redis.from_url(redis_url)
        msg = json.dumps({"kind": kind, "payload": payload}, default=str)
        r.publish(REDIS_CC_CHANNEL, msg)
    except Exception as e:
        logger.debug("events_pub publish failed: %s", e)
