"""Telegram alerting with delta filtering: only notify on NEW findings (Target + CVE/Anomaly) in last 24h."""
import os
from datetime import datetime, timedelta
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass

import requests

from src.database import get_session_factory, AlertSentModel
from src.http_client import safe_post, ENTERPRISE_HTTP_TIMEOUT

# Only send if we have not sent the same (target, finding_id) in this many hours.
ALERT_DEDUP_HOURS = 24


def _telegram_config() -> tuple[str, str]:
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    return token, chat_id


TELEGRAM_PREFIX = "[Weissman-Cyber-Intel] "

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
) -> bool:
    """
    Send a Telegram CVE/finding alert only if (target, finding_id) was not already
    alerted in the last 24 hours. Returns True if sent, False if skipped or failed.
    """
    target = (target or "").strip()[:512]
    finding_id = (finding_id or "").strip()[:512]
    if not target or not finding_id:
        return False
    if _was_alert_sent_recently(target, finding_id):
        return False
    if not send_telegram_alert(message):
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
    Send a Telegram fuzzer zero-day report alert only if this filename was not
    already alerted in the last 24 hours. Uses target="fuzzer", finding_id=filename.
    """
    filename = (filename or "").strip()[:512]
    if not filename:
        return False
    if _was_alert_sent_recently("fuzzer", filename):
        return False
    msg = format_fuzzer_report_alert(filename)
    if not send_telegram_alert(msg):
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
    """Send dark web Telegram alert; dedup by (target, source_url) in last 24h."""
    target = (target or "").strip()[:512]
    source_url = (source_url or "").strip()[:512]
    if not target or not source_url:
        return False
    finding_id = f"darkweb:{source_url}"
    if _was_alert_sent_recently(target, finding_id):
        return False
    msg = format_darkweb_alert(target, snippet, source_url)
    if not send_telegram_alert(msg):
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
    Send [Weissman-Discovery] UNKNOWN ASSET FOUND only if (client_id, asset_value) was not
    already sent in the last 24 hours.
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
    if not send_telegram_alert(msg):
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
    Send exploit-threat Telegram alert only if (target_name, repo_url) was not
    already sent in the last 24 hours. finding_id = repo_url for dedup.
    """
    target_name = (target_name or "").strip()[:512]
    repo_url = (repo_url or "").strip()[:512]
    if not target_name or not repo_url:
        return False
    if _was_alert_sent_recently(target_name, repo_url):
        return False
    msg = format_exploit_threat_alert(technology, target_name, repo_url)
    if not send_telegram_alert(msg):
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
