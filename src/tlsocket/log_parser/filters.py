import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

from tlsocket.log_parser.models import LogRecord

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION = re.compile(r"^(\d+)([smhd])$")

def parse_duration(text: str) -> timedelta:
    match = _DURATION.match(text.strip().lower())
    if match is None:
        raise ValueError(f"invalid duration {text!r} (use e.g. 30s, 15m, 1h, 2d)")
    return timedelta(seconds=int(match[1]) * _UNITS[match[2]])

def filter_since(records: Iterable[LogRecord], since: datetime) -> Iterator[LogRecord]:
    return (r for r in records if r.timestamp >= since)