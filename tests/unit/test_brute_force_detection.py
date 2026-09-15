import json
from datetime import datetime, timedelta

import pytest

from tlsocket.log_parser.models import LogRecord
from tlsocket.security import brute_force_detection as bfd


@pytest.fixture
def detector(tmp_path, monkeypatch):
    monkeypatch.setattr(bfd, "BRUTE_FORCE_STATE_FILE", tmp_path / "state.json")
    return bfd.BruteForceDetector(max_attempts=3, window_seconds=60, block_duration=10)

def _failed(ip, ts):
    return LogRecord(
        date=ts.strftime("%Y-%m-%d"), time=ts.strftime("%H:%M:%S"),
        level="WARNING", event_type="LOGIN_FAILED",
        username="victim", ip=ip, extra_info="",
        )

def test_blocks_after_max_attempts_within_window(detector):
    now = datetime.now().replace(microsecond=0)  # log chỉ lưu tới độ chính xác giây
    for i in range(3):
        detector.process_record(_failed("1.2.3.4", now + timedelta(seconds=i)))

    assert "1.2.3.4" in detector.blocked_ips
    assert detector.violation_count["1.2.3.4"] == 1
    last_ts = now + timedelta(seconds=2)
    assert detector.blocked_ips["1.2.3.4"] == last_ts + timedelta(seconds=10)

def test_ignores_non_login_failed_events(detector):
    rec = LogRecord(date="2026-01-01", time="12:00:00", level="INFO",
                    event_type="LOGIN_SUCCESS", username="a", ip="1.2.3.4",
                    extra_info="")
    detector.process_record(rec)
    assert detector.failed_attempts_history=={}

def test_ignores_missing_ip(detector):
    rec = LogRecord(date="2026-01-01", time="12:00:00", level="WARNING",
                    event_type="LOGIN_FAILED", username="a", ip="", extra_info="")
    detector.process_record(rec)
    assert detector.blocked_ips=={}

def test_old_attempts_outside_window_are_pruned(detector):
    now = datetime.now()
    detector.process_record(_failed("1.2.3.4", now))
    detector.process_record(_failed("1.2.3.4", now + timedelta(seconds=5)))
    assert "1.2.3.4" not in detector.blocked_ips

    detector.process_record(_failed("1.2.3.4", now + timedelta(seconds=70)))
    assert "1.2.3.4" not in detector.blocked_ips
    assert len(detector.failed_attempts_history["1.2.3.4"])==1

@pytest.mark.parametrize("prior_violations,multiplier", [
    (0,1),
    (1,5),
    (2,30),
    (3,1440),
])
def test_escalating_ban_duration(detector, prior_violations, multiplier):
    ip = "1.2.3.4"
    detector.violation_count[ip] = prior_violations
    now = datetime.now().replace(microsecond=0)
    for i in range (3):
        detector.process_record(_failed(ip, now + timedelta(seconds=i)))

    last_ts = now + timedelta(seconds=2)
    assert detector.blocked_ips[ip] == last_ts + timedelta(seconds=10 * multiplier)

def test_is_ip_blocked_true_while_active(detector):
    detector.blocked_ips["1.2.3.4"] = datetime.now() + timedelta(seconds=30)
    assert detector.is_ip_blocked("1.2.3.4") is True

def test_is_ip_blocked_false_and_self_cleans_after_expiry(detector):
    detector.blocked_ips["1.2.3.4"] = datetime.now() - timedelta(seconds=1)
    assert detector.is_ip_blocked("1.2.3.4") is False
    assert "1.2.3.4" not in detector.blocked_ips

def test_is_ip_blocked_unknown_ip(detector):
    assert detector.is_ip_blocked("9.9.9.9") is False

def test_get_remaining_ban_time_while_blocked(detector):
    detector.blocked_ips["1.2.3.4"] = datetime.now() + timedelta(seconds=30)
    remaining = detector.get_remaining_ban_time("1.2.3.4")
    assert 0 < remaining <= 30

def test_get_remaining_ban_time_when_not_blocked(detector):
    assert detector.get_remaining_ban_time("1.2.3.4") == 0

def test_save_and_load_state_roundtrip(detector):
    ip = "1.2.3.4"
    now = datetime.now()
    for i in range(3):
        detector.process_record(_failed(ip, now + timedelta(seconds=i)))
    assert detector.db_file.exists()

    d2 = bfd.BruteForceDetector(max_attempts=3, window_seconds=60, block_duration=10)
    assert d2.violation_count[ip]==1
    assert ip in d2.blocked_ips

def test_detect_brute_force_stream_blocks_ip_from_records(tmp_path, monkeypatch):
    monkeypatch.setattr(bfd, "BRUTE_FORCE_STATE_FILE", tmp_path / "state.json")
    now = datetime.now().replace(microsecond=0)
    records = [_failed("1.2.3.4", now + timedelta(seconds=i)) for i in range(3)]

    bfd.detect_brute_force_stream(records, max_attempts=3, window_seconds=60)

    saved = json.loads((tmp_path / "state.json").read_text())
    assert "1.2.3.4" in saved["blocked_ips"]

def test_load_state_with_corrupted_file_does_not_raise(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    state_file.write_text("{ not valid json")
    monkeypatch.setattr(bfd, "BRUTE_FORCE_STATE_FILE", state_file)

    d = bfd.BruteForceDetector(max_attempts=3, window_seconds=60, block_duration=10)
    assert d.blocked_ips=={}
    assert d.violation_count=={}