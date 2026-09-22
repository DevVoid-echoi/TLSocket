from datetime import datetime, timedelta, timezone

import pytest

from tlsocket.log_parser.filters import filter_since, parse_duration
from tlsocket.log_parser.models import LogRecord


@pytest.mark.parametrize("text, expected", [
    ("30s", timedelta(seconds=30)),
    ("15m", timedelta(minutes=15)),
    ("1h", timedelta(hours=1)),
    ("2d", timedelta(days=2)),
    (" 3d", timedelta(days=3)),
])
def test_parse_duration_valid(text, expected):
    assert parse_duration(text) == expected

@pytest.mark.parametrize("text", ["", "h", "1", "1w", "-5m", "1.5h", "5 m"])
def test_parse_duration_invalid(text):
    with pytest.raises(ValueError):
        parse_duration(text)

def test_filter_since_is_inclusive_at_the_boundary():
    def rec(minute):
        return LogRecord(timestamp=datetime(2026, 1, 1, 12, minute, tzinfo=timezone.utc),
                         level="INFO", event_type="LOGIN_SUCCESS", username="alice", ip="N/A", extra_info="")

    cutoff = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)
    kept = list(filter_since([rec(29), rec(30), rec(31)], cutoff))
    assert [r.timestamp.minute for r in kept] == [30, 31]