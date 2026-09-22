from datetime import datetime, timezone

from tlsocket.log_parser.analyzer import (
    failure_rate_over_time,
    peak_attack_hours,
    top_targeted_users,
)
from tlsocket.log_parser.models import LogRecord

UTC = timezone.utc


def _rec(event_type, ts, username="N/A", level="INFO", extra_info=""):
    return LogRecord(timestamp=ts, level=level, event_type=event_type,
                    username=username, ip="N/A", extra_info=extra_info)

def _t(hour, minute=0):
    return datetime(2026, 8, 27, hour, minute, tzinfo=UTC)

def test_peak_attack_hours_ranks_hours_by_attack_events():
    records = [
        _rec("LOGIN_FAILED", _t(15, 10)), _rec("LOGIN_FAILED", _t(15, 20)),
        _rec("RATE_LIMIT_EXCEEDED", _t(15, 50)),
        _rec("LOGIN_FAILED", _t(16, 5)), _rec("LOGIN_SUCCESS", _t(15, 30)) 
    ]
    assert peak_attack_hours(records) == [("2026-08-27 15:00", 3), ("2026-08-27 16:00", 1)]

def test_peak_attack_hours_respects_top_n():
    records = [_rec("LOGIN_FAILED", _t(h)) for h in (10, 11, 12)]
    assert len(peak_attack_hours(records, top_n=2)) == 2

def test_top_targeted_users_counts_failed_logins_per_username():
    records = [_rec("LOGIN_FAILED", _t(1), username="alice"),
               _rec("LOGIN_FAILED", _t(1), username="alice"),
               _rec("LOGIN_FAILED", _t(1), username="alice"),
               _rec("LOGIN_FAILED", _t(1), username="bob"),]
    assert top_targeted_users(records) == [("alice", 3), ("bob", 1)]

def test_top_targeted_users_ignores_noise():
    records = [_rec("LOGIN_FAILED", _t(1), username="Unknown"),
               _rec("LOGIN_FAILED", _t(1), username="N/A"),
               _rec("LOGIN_FAILED", _t(1), username="alice", extra_info="ALREADY_LOGGED_IN"),
               _rec("LOGIN_SUCCESS", _t(1), username="bob"),
            ]
    assert top_targeted_users(records) == []

def test_failures_rate_over_time_groups_into_hourly_buckets():
    records = [
        _rec("LOGIN_SUCCESS", _t(15, 5)), _rec("LOGIN_SUCCESS", _t(15, 10)),
        _rec("LOGIN_SUCCESS", _t(15, 20)), _rec("LOGIN_FAILED", _t(15, 40), level="WARNING"),
        _rec("LOGIN_FAILED", _t(16, 5), level="WARNING"),
    ]
    buckets = failure_rate_over_time(records)
    assert [(b.start, b.total, b.failures) for b in buckets] == [(_t(15), 4, 1), (_t(16), 1, 1)]
    assert [b.rate for b in buckets] == [0.25, 1.0]

def test_failures_rate_over_time_custom_bucket_and_empty_input():
    records = [_rec("LOGIN_FAILED", _t(15, 15)), _rec("LOGIN_FAILED", _t(15, 20))]
    assert len(failure_rate_over_time(records, bucket_minutes=10)) == 2
    assert failure_rate_over_time([]) == []