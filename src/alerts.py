"""Alerting with delta filtering: only notify on NEW findings (Target + CVE/Anomaly) in last 24h.

Supported channels:
  - Telegram   (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)
  - Slack      (SLACK_WEBHOOK_URL)
  - Email      (SMTP_HOST + SMTP_PORT + SMTP_USER + SMTP_PASSWORD + ALERT_EMAIL_TO)
  - PagerDuty  (PAGERDUTY_ROUTING_KEY) — Events API v2 with auto-deduplication
"""
import logging
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

import requests

from src.database import get_session_factory, AlertSentModel
from src.http_client import safe_post, ENTERPRISE_HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# Only send if we have not sent the same (target, finding_id) in this many hours.
ALERT_DEDUP_HOURS = 24


def _telegram_config() -> tuple[str, str]:
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    return token, chat_id


TELEGRAM_PREFIX = "[Weissman-Cyber-Intel] "

# ---------------------------------------------------------------------------
# Slack alerts
# ---------------------------------------------------------------------------

def send_slack_alert(message: str) -> bool:
    """
    Send a plain-text message to the configured Slack incoming webhook.
    Returns True on success, False if not configured or request fails.
    """
    webhook_url = (os.getenv("SLACK_WEBHOOK_URL") or "").strip()
    if not webhook_url:
        return False
    try:
        r = safe_post(
            webhook_url,
            json={"text": message},
            timeout=ENTERPRISE_HTTP_TIMEOUT,
        )
        return r.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Email (SMTP) alerts
# ---------------------------------------------------------------------------

def _smtp_config() -> tuple[str, int, str, str, str] | None:
    """Return (host, port, user, password, to_addr) or None if not configured."""
    host = (os.getenv("SMTP_HOST") or "").strip()
    to_addr = (os.getenv("ALERT_EMAIL_TO") or "").strip()
    if not host or not to_addr:
        return None
    try:
        port = int(os.getenv("SMTP_PORT") or "587")
    except ValueError:
        port = 587
    user = (os.getenv("SMTP_USER") or "").strip()
    password = (os.getenv("SMTP_PASSWORD") or "").strip()
    return host, port, user, password, to_addr


def send_email_alert(subject: str, body: str) -> bool:
    """
    Send an email alert via SMTP. Uses TLS when port != 465.
    Returns True on success, False if not configured or send fails.
    """
    cfg = _smtp_config()
    if not cfg:
        return False
    host, port, user, password, to_addr = cfg
    # Use explicitly configured user as the From address; fall back to a
    # generic address only when SMTP_USER is not set.
    from_addr = user if user else "weissman-alerts@localhost"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.attach(MIMEText(body, "plain"))
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
                if user and password:
                    smtp.login(user, password)
                smtp.sendmail(from_addr, [to_addr], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if user and password:
                    smtp.login(user, password)
                smtp.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except Exception as exc:
        logger.warning("Email alert failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# PagerDuty Events API v2
# ---------------------------------------------------------------------------

def send_pagerduty_alert(
    summary: str,
    severity: str = "critical",
    source: str = "weissman-cybersecurity",
    dedup_key: str | None = None,
    custom_details: dict | None = None,
) -> bool:
    """
    Send a trigger event to PagerDuty Events API v2.

    Parameters
    ----------
    summary:
        Brief text summary of the alert (e.g., "Critical XSS vulnerability in example.com").
    severity:
        One of: critical, error, warning, info. Defaults to critical.
    source:
        Source identifier (defaults to "weissman-cybersecurity").
    dedup_key:
        Deduplication key. If provided, PagerDuty will automatically dedupe events
        with the same key. Recommended format: "{client_id}:{finding_title}".
    custom_details:
        Optional dict of additional data to include in the alert payload.

    Returns
    -------
    bool
        True if the event was successfully enqueued, False if not configured or request fails.

    Notes
    -----
    Requires PAGERDUTY_ROUTING_KEY environment variable. If not set, returns False silently.
    See: https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTgw-events-api-v2-overview
    """
    routing_key = (os.getenv("PAGERDUTY_ROUTING_KEY") or "").strip()
    if not routing_key:
        return False
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary[:1024],
            "severity": severity.lower() if severity.lower() in ("critical", "error", "warning", "info") else "critical",
            "source": source[:255],
        },
    }
    if dedup_key:
        payload["dedup_key"] = dedup_key[:255]
    if custom_details:
        payload["payload"]["custom_details"] = custom_details
    try:
        r = safe_post(url, json=payload, timeout=ENTERPRISE_HTTP_TIMEOUT)
        return r.status_code == 202  # PagerDuty returns 202 Accepted
    except Exception as exc:
        logger.warning("PagerDuty alert failed: %s", exc)
        return False


def resolve_pagerduty_alert(dedup_key: str) -> bool:
    """
    Send a resolve event to PagerDuty for a given dedup_key.

    This should be called when a finding status is changed to "fixed" in the database.
    Integration example (Python webhooks/background job):
        from src.alerts import resolve_pagerduty_alert
        from src.database import get_session_factory, VulnerabilityModel

        # Monitor vulnerabilities table for status changes to FIXED
        session = get_session_factory()()
        vulns = session.query(VulnerabilityModel).filter(
            VulnerabilityModel.status == "FIXED",
            VulnerabilityModel.status_changed_at >= datetime.utcnow() - timedelta(minutes=5)
        ).all()
        for v in vulns:
            dedup_key = f"{v.client_id}:{v.finding_id}"
            resolve_pagerduty_alert(dedup_key)

    Parameters
    ----------
    dedup_key:
        The same deduplication key used when the alert was triggered.

    Returns
    -------
    bool
        True if the resolve event was successfully enqueued, False otherwise.
    """
    routing_key = (os.getenv("PAGERDUTY_ROUTING_KEY") or "").strip()
    if not routing_key or not dedup_key:
        return False
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": routing_key,
        "event_action": "resolve",
        "dedup_key": dedup_key[:255],
    }
    try:
        r = safe_post(url, json=payload, timeout=ENTERPRISE_HTTP_TIMEOUT)
        return r.status_code == 202
    except Exception as exc:
        logger.warning("PagerDuty resolve failed: %s", exc)
        return False


def send_telegram_alert(message: str, parse_mode: str = "Markdown") -> bool:
    """
    Send a message to the configured Telegram chat via Bot API sendMessage.
    All alerts are prefixed with [Weissman-Cyber-Intel].
    Returns True if sent successfully, False otherwise (missing config or request failure).
    """
    token, chat_id = _telegram_config()
    if not token or not chat_id:
        return False
    if message and (message.strip().startswith("[Weissman-") or message.strip().startswith(TELEGRAM_PREFIX.strip())):
        text = message
    else:
        text = (TELEGRAM_PREFIX + message) if message else message
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        r = safe_post(
            url,
            json={"chat_id": chat_id, "text": text, "parse_mode": parse_mode},
            timeout=ENTERPRISE_HTTP_TIMEOUT,
        )
        return r.status_code == 200
    except Exception:
        return False


def _was_alert_sent_recently(target: str, finding_id: str) -> bool:
    """True if (target, finding_id) was already sent in the last ALERT_DEDUP_HOURS."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            since = datetime.utcnow() - timedelta(hours=ALERT_DEDUP_HOURS)
            exists = (
                db.query(AlertSentModel)
                .filter(
                    AlertSentModel.target == target,
                    AlertSentModel.finding_id == finding_id,
                    AlertSentModel.alerted_at >= since,
                )
                .limit(1)
                .first()
            )
            return exists is not None
        finally:
            db.close()
    except Exception:
        return False


def _record_alert_sent(target: str, finding_id: str) -> None:
    """Record that we sent an alert for (target, finding_id)."""
    try:
        factory = get_session_factory()
        db = factory()
        try:
            row = AlertSentModel(target=target, finding_id=finding_id)
            db.add(row)
            db.commit()
        finally:
            db.close()
    except Exception:
        pass


def send_cve_alert_if_new(
    target: str,
    finding_id: str,
    message: str,
    client_id: str | None = None,
    severity: str = "critical",
) -> bool:
    """
    Send CVE/finding alert (Telegram + Slack + Email + PagerDuty) only if (target, finding_id)
    was not already alerted in the last 24 hours. Returns True if at least one channel succeeded.

    Parameters
    ----------
    target:
        Target URL or domain.
    finding_id:
        Unique identifier for the finding (CVE ID, vulnerability type, etc.).
    message:
        Alert message text.
    client_id:
        Optional client identifier for PagerDuty deduplication key.
    severity:
        Severity level for PagerDuty (critical, error, warning, info). Defaults to critical.
    """
    target = (target or "").strip()[:512]
    finding_id = (finding_id or "").strip()[:512]
    if not target or not finding_id:
        return False
    if _was_alert_sent_recently(target, finding_id):
        return False
    tg_ok = send_telegram_alert(message)
    slack_ok = send_slack_alert(message)
    email_ok = send_email_alert(f"[Weissman] Security Finding: {finding_id}", message)
    # PagerDuty with deduplication key: client_id:finding_id
    dedup_key = f"{client_id or 'unknown'}:{finding_id}" if client_id else finding_id
    pd_ok = send_pagerduty_alert(
        summary=f"Critical security finding: {finding_id} on {target}",
        severity=severity,
        dedup_key=dedup_key,
        custom_details={"target": target, "finding_id": finding_id, "message": message[:500]},
    )
    if not (tg_ok or slack_ok or email_ok or pd_ok):
        return False
    _record_alert_sent(target, finding_id)
    try:
        from src.events_pub import publish_command_center_event
        publish_command_center_event("critical_cve", {"target": target, "finding_id": finding_id, "message": message})
    except Exception:
        pass
    return True


def send_fuzzer_alert_if_new(filename: str) -> bool:
    """
    Send fuzzer zero-day report alert (Telegram + Slack + email) only if this filename
    was not already alerted in the last 24 hours.
    """
    filename = (filename or "").strip()[:512]
    if not filename:
        return False
    if _was_alert_sent_recently("fuzzer", filename):
        return False
    msg = format_fuzzer_report_alert(filename)
    tg_ok = send_telegram_alert(msg)
    slack_ok = send_slack_alert(msg)
    email_ok = send_email_alert("[Weissman] New Zero-Day Potential Report", msg)
    if not (tg_ok or slack_ok or email_ok):
        return False
    _record_alert_sent("fuzzer", filename)
    try:
        from src.events_pub import publish_command_center_event
        publish_command_center_event("fuzzer_anomaly", {"filename": filename})
    except Exception:
        pass
    return True


def format_cve_alert(target: str, severity: str, title: str, description: str, source: str = "") -> str:
    """Build a Markdown alert message for a matched CVE/finding."""
    desc_short = (description or "")[:300].replace("*", "\\*")
    return (
        f"*🔒 Security Finding*\n\n"
        f"*Target:* `{target}`\n"
        f"*Severity:* {severity}\n"
        f"*Title:* {title}\n\n"
        f"{desc_short}\n\n"
        f"Source: {source or 'intel'}"
    )


def format_fuzzer_report_alert(filename: str) -> str:
    """Build alert message when a new zero-day potential report is generated."""
    return f"🚨 *New Zero-Day Potential Report Generated*\n\n`{filename}`"


def format_exploit_threat_alert(technology: str, target_name: str, repo_url: str = "") -> str:
    """Build Telegram message for exploit-intel: attack tool for [Technology], target [Target Name]."""
    tech = (technology or "unknown").replace("*", "\\*")
    target = (target_name or "target").replace("*", "\\*")
    link = f"\nRepo: {repo_url}" if repo_url else ""
    return (
        f"⚠️ *CRITICAL THREAT*\n\n"
        f"A new attack tool for *{tech}* was found on GitHub. "
        f"Your target *{target}* is running this technology. Risk: High.{link}"
    )


def format_darkweb_alert(target: str, snippet: str, source_url: str) -> str:
    """Build Telegram message for dark web finding."""
    t = (target or "target").replace("*", "\\*")[:200]
    s = (snippet or "")[:250].replace("*", "\\*")
    u = (source_url or "")[:200]
    return (
        f"🌑 *DARK WEB ALERT*\n\n"
        f"Potential threat/leak detected for *{t}* on a .onion site.\n\n"
        f"Description: {s}\n\n"
        f"Source: `{u}`\n\n"
        f"System is now shifting all resources to verify impact."
    )


def send_darkweb_alert_if_new(target: str, source_url: str, snippet: str) -> bool:
    """Send dark web alert (Telegram + Slack + email); dedup by (target, source_url) in last 24h."""
    target = (target or "").strip()[:512]
    source_url = (source_url or "").strip()[:512]
    if not target or not source_url:
        return False
    finding_id = f"darkweb:{source_url}"
    if _was_alert_sent_recently(target, finding_id):
        return False
    msg = format_darkweb_alert(target, snippet, source_url)
    tg_ok = send_telegram_alert(msg)
    slack_ok = send_slack_alert(msg)
    email_ok = send_email_alert(f"[Weissman] Dark Web Alert: {target}", msg)
    if not (tg_ok or slack_ok or email_ok):
        return False
    _record_alert_sent(target, finding_id)
    try:
        from src.events_pub import publish_command_center_event
        publish_command_center_event("darkweb", {"target": target, "source_url": source_url, "snippet": snippet})
        banner_msg = f"WARNING: DARK WEB INTEL MATCH - SENSITIVE DATABASE LEAK DETECTED FOR {target.upper()}."
        publish_command_center_event("emergency_alert", {"message": banner_msg, "target": target, "type": "darkweb"})
    except Exception:
        pass
    return True


DISCOVERY_PREFIX = "[Weissman-Discovery] "


def format_discovery_alert(asset_type: str, asset_value: str, client_name: str, confidence: str = "high") -> str:
    """Build Telegram message for Shadow IT / unknown asset discovery."""
    t = (asset_type or "asset").replace("*", "\\*")
    v = (asset_value or "").replace("*", "\\*")[:200]
    c = (client_name or "client").replace("*", "\\*")
    conf = (confidence or "high").replace("*", "\\*")
    return (
        f"{DISCOVERY_PREFIX}*UNKNOWN ASSET FOUND*\n\n"
        f"*Client:* `{c}`\n"
        f"*Type:* {t}\n"
        f"*Asset:* `{v}`\n"
        f"*Confidence:* {conf}\n\n"
        f"This asset was not in the client's documented scope. Possible Shadow IT."
    )


def send_discovery_alert_if_new(
    client_id: str,
    client_name: str,
    asset_type: str,
    asset_value: str,
    confidence: str = "high",
) -> bool:
    """
    Send [Weissman-Discovery] UNKNOWN ASSET FOUND (Telegram + Slack + email) only if
    (client_id, asset_value) was not already sent in the last 24 hours.
    """
    client_id = (client_id or "").strip()[:512]
    client_name = (client_name or "").strip()[:512]
    asset_type = (asset_type or "asset").strip()[:128]
    asset_value = (asset_value or "").strip()[:512]
    if not client_id or not asset_value:
        return False
    finding_id = f"discovery:{asset_type}:{asset_value}"
    if _was_alert_sent_recently(client_id, finding_id):
        return False
    msg = format_discovery_alert(asset_type, asset_value, client_name, confidence)
    tg_ok = send_telegram_alert(msg)
    slack_ok = send_slack_alert(msg)
    email_ok = send_email_alert(f"[Weissman] Unknown Asset Found: {asset_value}", msg)
    if not (tg_ok or slack_ok or email_ok):
        return False
    _record_alert_sent(client_id, finding_id)
    try:
        from src.events_pub import publish_command_center_event
        publish_command_center_event("discovery", {"client_name": client_name, "asset_type": asset_type, "asset_value": asset_value})
    except Exception:
        pass
    return True


def send_exploit_alert_if_new(target_name: str, technology: str, repo_url: str) -> bool:
    """
    Send exploit-threat alert (Telegram + Slack + email) only if (target_name, repo_url)
    was not already sent in the last 24 hours.
    """
    target_name = (target_name or "").strip()[:512]
    repo_url = (repo_url or "").strip()[:512]
    if not target_name or not repo_url:
        return False
    if _was_alert_sent_recently(target_name, repo_url):
        return False
    msg = format_exploit_threat_alert(technology, target_name, repo_url)
    tg_ok = send_telegram_alert(msg)
    slack_ok = send_slack_alert(msg)
    email_ok = send_email_alert(f"[Weissman] Critical Exploit Threat: {technology}", msg)
    if not (tg_ok or slack_ok or email_ok):
        return False
    _record_alert_sent(target_name, repo_url)
    try:
        from src.events_pub import publish_command_center_event
        publish_command_center_event("exploit", {"target_name": target_name, "technology": technology, "repo_url": repo_url})
        banner_msg = f"WARNING: GITHUB EXPLOIT MATCH - ATTACK TOOL FOR {technology.upper()} TARGETING {target_name.upper()}."
        publish_command_center_event("emergency_alert", {"message": banner_msg, "target": target_name, "type": "exploit"})
    except Exception:
        pass
    return True
