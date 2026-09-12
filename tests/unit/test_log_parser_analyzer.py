import pytest

from tlsocket.log_parser.models import LogRecord
from tlsocket.log_parser.analyzer import analyze

def _rec(event_type, ip="N/A", level="INFO"):
    return LogRecord(date="2026-01-01", time="00:00:00", level=level,
                    event_type=event_type, username="N/A", ip=ip, extra_info="")

def test_analyze_empty_records():
    result = analyze([])
    assert result["total_requests"] == 0
    assert result["error_rate"] == 0
    assert result["brute_force_alert"] is False
    assert result["ddos_alert"] is False

def test_analyze_counts_events():
    records = [
        _rec("LOGIN_SUCCESS", ip="1.1.1.1"),
        _rec("LOGIN_FAILED", ip="1.1.1.1", level="WARNING"),
        _rec("LOGIN_FAILED", ip="2.2.2.2", level="WARNING"),
        _rec("KICK"),
        _rec("BAN"),
        _rec("CONNECTION_ERROR"),
    ]
    result = analyze(records)
    assert result["total_requests"] == 6
    assert result["successful_logins"] == 1 
    assert result["failed_logins"] == 2
    assert result["kicked_users"] == 1 
    assert result["banned_users"] == 1
    assert result["error_count"] == 1
    assert result["warning"] == 2

def test_analyze_ip_aggregation_excludes_na():
    records = [
        _rec("LOGIN_SUCCESS", ip="1.1.1.1"),
        _rec("LOGIN_SUCCESS", ip="1.1.1.1"),
        _rec("LOGIN_SUCCESS", ip="2.2.2.2"),
        _rec("LOGIN_SUCCESS", ip="N/A"),
    ]
    result = analyze(records)
    assert result["unique_ip_count"] == 2
    assert result["all_ips"] == [("1.1.1.1", 2), ("2.2.2.2", 1)]
    assert result["top_5_IPs"] == [("1.1.1.1", 2), ("2.2.2.2", 1)]

def test_analyze_error_rate_is_fraction_of_total():
    records = [_rec("CONNECTION_ERROR")] +[_rec("LOGIN_SUCCESS")] * 3
    result = analyze(records)
    assert result["error_rate"] == 0.25

@pytest.mark.parametrize("event_type", ["RATE_LIMIT_EXCEEDED", "[ALERT] BRUTE_FORCE_ATTEMPT"])
def test_analyze_flags_brute_force(event_type):
    result = analyze([_rec(event_type, ip="9.9.9.9")])
    assert result["brute_force_alert"] is True
    assert result["suspicious_IPs"] == {"9.9.9.9": 1}

def test_analyze_flags_ddos():
    result = analyze([_rec("CONNECTION_LIMIT_REACHED", ip="9.9.9.9")])
    assert result["ddos_alert"] is True

def test_analyze_no_false_alerts_on_normal_traffic():
    result = analyze([_rec("LOGIN_SUCCESS", ip="1.1.1.1")])
    assert result["brute_force_alert"] is False
    assert result["ddos_alert"] is False