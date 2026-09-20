import json
from datetime import datetime, timezone

import pytest

from tlsocket.log_parser.models import LogRecord
from tlsocket.log_parser.parser import iter_record, parse_line


def _line(**fields):
    base = {"ts": "2026-08-27T15:00:15+00:00", "level": "INFO", "event": "LOGIN_SUCCESS"}
    return json.dumps({**base, **fields})

def test_parse_line_basic():
    assert parse_line(_line(username="alice", ip="127.0.0.1")) == LogRecord(
        timestamp=datetime(2026, 8, 27, 15, 0, 15, tzinfo=timezone.utc),
        level="INFO", event_type="LOGIN_SUCCESS",
        username="alice", ip="127.0.0.1", extra_info="",
    )

def parse_line_keep_microseconds():
    rec = parse_line(_line(ts="2026-08-27T15:00:15.250000+00:00"))
    assert rec.timestamp.microsecond == 250000

def parse_line_optional_fields_default():
    rec = parse_line(_line(extra_info="reason=BANNED"))
    assert rec.extra_info == "reason=BANNED"
    assert rec.username == "N/A"
    assert rec.ip == "N/A"

def parse_line_naive_timestamp_treated_as_utc():
    rec = parse_line(_line(ts="2026-08-27T15:00:15"))
    assert rec.timestamp.tzinfo == timezone.dst

def parse_line_alert_record_with_extra_fields():
    rec = parse_line(_line(
        event="BRUTE_FORCE_ATTEMPT",
        level="WARNING",
        ip="10.0.0.1",
        failed_attempts=5,
        window_seconds=60
    ))
    assert rec["event"] == "BRUTE_FORCE_ATTEMPT"
    assert rec["ip"] == "10.0.0.1"

@pytest.mark.parametrize("line", [
    "",
    "   ",
    "not json at all",
    "{ broken",
    "[1, 2, 3]",                                                    # JSON hợp lệ nhưng không phải object
    '"just a string"',
    "42",
    json.dumps({"level": "INFO", "event": "X"}),                    # thiếu ts
    json.dumps({"ts": "2026-08-27T15:00:15+00:00", "event": "X"}),  # thiếu level
    json.dumps({"ts": "not a date", "level": "INFO", "event": "X"}),
    "2026-08-27 15:00:15 INFO LOGIN_SUCCESS username=alice",
])
def test_parse_line_empty_or_comment_returns_none(line):
    assert parse_line(line) is None

def test_iter_record_skips_bad_lines(tmp_path):
    log_file = tmp_path/ "test.log"
    lines = [
        _line(username="alice", ip="1.1.1.1"),
        "# comment",
        "garbage",
        "",
        _line(username="bob", ip="2.2.2.2"),
    ]
    log_file.write_text("\n".join(lines) + "\n")
    records = list(iter_record(str(log_file)))
    assert [r.username for r in records] == ["alice", "bob"]

def test_iter_record_empty_file(tmp_path):
    log_file = tmp_path / "emtpy.log"
    log_file.write_text("")
    assert list(iter_record(str(log_file))) == []

def test_iter_record_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(iter_record(str(tmp_path / "missing.log")))
        