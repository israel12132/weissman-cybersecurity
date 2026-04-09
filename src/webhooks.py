"""
Webhook push: POST findings to user-configured URLs (Jira, Splunk, etc.).
X-Weissman-Signature: HMAC-SHA256 for authenticity.
"""
import hmac
import hashlib
import json
import logging
import os
from typing import Any

import requests

from src.database import get_session_factory, WebhookModel

logger = logging.getLogger(__name__)

WEBHOOK_SECRET_ENV = "WEBHOOK_SECRET"


def _sign_payload(body: bytes, secret: str) -> str:
    """HMAC-SHA256 of body; return hex digest for X-Weissman-Signature."""
    if not secret:
        secret = os.getenv(WEBHOOK_SECRET_ENV) or ""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def build_webhook_payload(
    run_id: int | str,
    run_created: str,
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a structured payload for Jira/Splunk compatibility.
    Fields: summary, findings (array of { title, description, severity, cvss, remediation, client_id }).
    """
    from src.pdf_export import cvss_score_from_anomaly, remediation_for_anomaly, weissman_security_score

    findings_export = []
    for item in findings:
        f = item.get("finding") or {}
        title = f.get("title") or "Finding"
        desc = f.get("description") or ""
        sev = f.get("severity") or "medium"
        score = cvss_score_from_anomaly(desc, sev)
        remed = remediation_for_anomaly(desc)
        findings_export.append({
            "title": title,
            "description": desc[:1000],
            "severity": sev,
            "cvss_score": round(score, 1),
            "remediation": remed,
            "client_id": item.get("client_id"),
            "relevance_note": item.get("relevance_note"),
        })
    by_severity = summary.get("by_severity") or {}
    weissman_rating = weissman_security_score(by_severity)
    return {
        "source": "Weissman-cybersecurity",
        "report_id": str(run_id),
        "timestamp": run_created,
        "summary": summary,
        "weissman_security_rating": weissman_rating,
        "findings": findings_export,
        "total_findings": len(findings_export),
    }


WEBHOOK_MAX_RETRIES = 5
WEBHOOK_BACKOFF_BASE_SECONDS = 1


def push_findings_to_webhooks(payload: dict[str, Any]) -> None:
    """POST payload to all enabled webhook URLs. Phase 2: retry with exponential backoff (max 5 retries). Logs errors; never raises."""
    import time
    try:
        factory = get_session_factory()
        db = factory()
        try:
            webhooks = db.query(WebhookModel).filter(WebhookModel.enabled == 1).all()
        finally:
            db.close()
    except Exception as e:
        logger.warning("Webhook fetch error: %s", e)
        return

    body_str = json.dumps(payload, default=str)
    body_bytes = body_str.encode("utf-8")
    for w in webhooks:
        url = (w.url or "").strip()
        if not url:
            continue
        secret = (w.secret or "").strip() or os.getenv(WEBHOOK_SECRET_ENV, "")
        signature = _sign_payload(body_bytes, secret)
        headers = {
            "Content-Type": "application/json",
            "X-Weissman-Signature": signature,
        }
        last_error = None
        for attempt in range(WEBHOOK_MAX_RETRIES + 1):
            try:
                from src.http_client import safe_post, ENTERPRISE_HTTP_TIMEOUT
                r = safe_post(url, data=body_bytes, headers=headers, timeout=ENTERPRISE_HTTP_TIMEOUT)
                if r.status_code >= 400:
                    last_error = f"HTTP {r.status_code}"
                    if attempt < WEBHOOK_MAX_RETRIES:
                        time.sleep(WEBHOOK_BACKOFF_BASE_SECONDS ** attempt)
                        continue
                    logger.warning("Webhook POST %s returned %s", url[:80], r.status_code)
                else:
                    break
            except Exception as e:
                last_error = str(e)
                if attempt < WEBHOOK_MAX_RETRIES:
                    delay = WEBHOOK_BACKOFF_BASE_SECONDS ** attempt
                    logger.debug("Webhook POST attempt %s failed for %s, retry in %ss: %s", attempt + 1, url[:80], delay, e)
                    time.sleep(delay)
                else:
                    logger.warning("Webhook POST failed for %s after %s attempts: %s", url[:80], WEBHOOK_MAX_RETRIES + 1, e)


def push_scan_complete_to_webhooks(run_ids: list[int], tenant_id: int | None, completed_at: str) -> None:
    """POST scan_complete event to all enabled webhooks (tenant-scoped). Payload: event, run_ids, tenant_id, completed_at. No mock data."""
    import time
    try:
        factory = get_session_factory()
        db = factory()
        try:
            q = db.query(WebhookModel).filter(WebhookModel.enabled == 1)
            if tenant_id is not None:
                q = q.filter(WebhookModel.tenant_id == tenant_id)
            webhooks = q.all()
        finally:
            db.close()
    except Exception as e:
        logger.warning("Webhook fetch error: %s", e)
        return
    payload = {
        "event": "scan_complete",
        "source": "Weissman-cybersecurity",
        "run_ids": run_ids,
        "tenant_id": tenant_id,
        "completed_at": completed_at,
    }
    body_str = json.dumps(payload, default=str)
    body_bytes = body_str.encode("utf-8")
    for w in webhooks:
        url = (w.url or "").strip()
        if not url:
            continue
        secret = (getattr(w, "secret", None) or "").strip() or os.getenv(WEBHOOK_SECRET_ENV, "")
        signature = _sign_payload(body_bytes, secret)
        headers = {"Content-Type": "application/json", "X-Weissman-Signature": signature}
        for attempt in range(WEBHOOK_MAX_RETRIES + 1):
            try:
                from src.http_client import safe_post, ENTERPRISE_HTTP_TIMEOUT
                r = safe_post(url, data=body_bytes, headers=headers, timeout=ENTERPRISE_HTTP_TIMEOUT)
                if r.status_code < 400:
                    break
                if attempt < WEBHOOK_MAX_RETRIES:
                    time.sleep(WEBHOOK_BACKOFF_BASE_SECONDS ** attempt)
            except Exception as e:
                if attempt >= WEBHOOK_MAX_RETRIES:
                    logger.warning("Webhook scan_complete POST failed for %s: %s", url[:80], e)
                else:
                    time.sleep(WEBHOOK_BACKOFF_BASE_SECONDS ** attempt)
