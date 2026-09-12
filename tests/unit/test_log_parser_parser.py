import pytest

from tlsocket.log_parser.models import LogRecord
from tlsocket.log_parser.parser import iter_record, parse_line

def test_parse_line_basic():
    line = "2026-08-27 15:00:15 INFO LOGIN_SUCCESS username=alice ip=127.0.0.1"
    assert parse_line(line) == LogRecord(
        date="2026-08-27", time="15:00:15", level="INFO",
        event_type="LOGIN_SUCCESS", username="alice", ip="127.0.0.1",
        extra_info="N/A",
    )

@pytest.mark.parametrize("line", ["", " ", "# a comment"])
def test_parse_line_empty_or_comment_returns_none(line):
    assert parse_line(line) is None

def test_parse_line_too_few_tokens_returns_none():
    assert parse_line("2026-08-27 15:00:15 INFO") is None 

def test_parse_line_alert_event_type_joins_two_tokens():
    line = "2026-08-27 15:01:00 WARNING [ALERT] BRUTE_FORCE_ATTEMPT ip=10.0.0.1"
    rec = parse_line(line)
    assert rec.event_type=="[ALERT] BRUTE_FORCE_ATTEMPT"
    assert rec.ip=="10.0.0.1"

def test_parse_line_unknown_key_goes_to_extra_info():
    rec = parse_line("2026-08-27 15:00:15 WARNING KICK reason=spam")
    assert rec.username == "N/A"
    assert rec.ip == "N/A"
    assert rec.extra_info == "reason=spam"

def test_parse_line_bare_token_kept_as_is():
    rec = parse_line("2026-08-27 15:00:15 WARNING KICK username=bob by_admin")
    assert rec.extra_info == "by_admin"

def test_iter_record_skips_bad_lines(tmp_path):
    log_file = tmp_path/ "test.log"
    log_file.write_text(
        "2026-08-27 15:00:15 INFO LOGIN_SUCCESS username=alice ip=1.1.1.1\n"
        "# comment\n"
        "garbage\n"
        "2026-08-27 15:00:20 WARNING LOGIN_FAILED username=bob ip=2.2.2.2\n"
    )
    records = list(iter_record(str(log_file)))
    assert [r.username for r in records] == ["alice", "bob"]

def test_iter_record_empty_file(tmp_path):
    log_file = tmp_path / "emtpy.log"
    log_file.write_text("")
    assert list(iter_record(str(log_file))) == []

def test_iter_record_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(iter_record(str(tmp_path / "missing.log")))
        