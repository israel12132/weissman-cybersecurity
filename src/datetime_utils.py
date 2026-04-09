"""Israel time (Asia/Jerusalem) for display and timestamps. DB continues to store UTC."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Jerusalem")
FMT = "%Y-%m-%d %H:%M:%S"
FMT_SHORT = "%Y-%m-%d %H:%M"


def now_ist() -> datetime:
    """Current time in Israel (Asia/Jerusalem)."""
    return datetime.now(IST)


def to_ist(dt: datetime | None) -> datetime | None:
    """Convert naive UTC datetime to Israel time. If already aware, convert to IST."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def format_ist(dt: datetime | None, short: bool = False) -> str:
    """Format datetime for display in Israel time. Accepts naive (assumed UTC) or aware."""
    if dt is None:
        return ""
    ist = to_ist(dt)
    return ist.strftime(FMT_SHORT if short else FMT)
