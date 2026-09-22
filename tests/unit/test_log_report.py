from datetime import datetime, timezone

from tlsocket.log_parser.models import LogRecord
from tlsocket.log_parser.report import build_report, to_json, to_table


def _rec(event_type, username="N/A", ip="N/A", level="INFO"):
    return LogRecord(timestamp=datetime(2026, 1, 1, 15, tzinfo=timezone.utc),
                     level=level, event_type=event_type, username=username, ip=ip, extra_info="")

def test_build_report_merges_analyze_and_analytics():
    records = [
        _rec("LOGIN SUCCESS", ip="1.1.1.1"),
        _rec("LOGIN_FAILED", username="bob", ip="2.2.2.2", level="WARNING"),
    ]
    report = build_report(records)
    assert report["total_requests"] == 2
    assert report["top_targeted_users"] == [("bob", 1)]
    assert report["peak_attack_hours"] == [("2026-01-01 15:00", 1)]
    assert report["failure_rate_over_time"][0]["rate"] == 0.5

def test_build_report_accepts_a_generator_only_once():
    def gen():
        yield _rec("LOGIN_FAILED", username="bob", level="WARNING")
        yield _rec("LOGIN_FAILED", username="bob", level="WARNING")

    report = build_report(gen())
    assert report["total_requests"] == 2
    assert report["failed_logins"] == 2
    assert report["top_targeted_users"] == [("bob", 2)]
    assert report["peak_attack_hours"] == [("2026-01-01 15:00", 2)]
    assert report["failure_rate_over_time"][0]["rate"] == 1

def test_to_json_roundtrips():
    import json
    report = build_report([_rec("LOGIN_SUCCESS", ip="1.1.1.1")])
    assert json.loads(to_json(report))["total_requests"] == 1

def test_to_table_handles_empty_sections():
    report = build_report([])
    table = to_table(report)
    assert "Total requests:       0" in table
    assert "none" in table

def test_to_table_shows_alert_flags():
    report = build_report([_rec("RATE_LIMIT_EXCEEDED", ip="9.9.9.9")])
    table = to_table(report)
    assert "Brute-force alert: YES" in table
    assert "DDoS alert: NO" in table

def test_to_table_error_rate():
    report = build_report([_rec("CONNECTION_ERROR")])
    table = to_table(report)
    assert "Errors:               1 (100.0%)" in table