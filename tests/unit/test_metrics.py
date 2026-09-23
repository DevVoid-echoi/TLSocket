from prometheus_client import generate_latest

from tlsocket import metrics
from tlsocket.server_side.logs_management.record_logs import log_event


def _value(counter_or_gauge, **lables):
    child = counter_or_gauge.labels(**lables) if lables else counter_or_gauge
    return child._value.get()

def test_login_events_increment_login_total():
    before_ok = _value(metrics.logins_total, result="success")
    log_event("LOGIN_SUCCESS", username="metric_a", ip="1.2.3.1")
    assert _value(metrics.logins_total, result="success") == before_ok + 1

    before_fail = _value(metrics.logins_total, result="failed")
    log_event("LOGIN_FAILED", username="metric_b", ip="1.2.3.2")
    assert _value(metrics.logins_total, result="failed") == before_fail + 1

def test_register_events_increment_registration_total():
    before_ok = _value(metrics.registration_total, result="success")
    log_event("REGISTER_SUCCESS", username="metric_c")
    assert _value(metrics.registration_total, result="success") == before_ok + 1

    before_fail = _value(metrics.registration_total, result="failed")
    log_event("REGISTER_FAILED", username="metric_d")
    assert _value(metrics.registration_total, result="failed") == before_fail + 1

def test_user_connected_increments_connections_total():
    before = _value(metrics.connection_total)
    log_event("USER_CONNECTED", ip="1.2.3.3")
    assert _value(metrics.connection_total) == before + 1

def test_connection_active_reflects_registry_size():
    from tlsocket.server_side.client_registry import Session
    from tlsocket.server_side.handlers import client_handler as ch

    ch.registry.reset()
    assert metrics.connection_active.collect()[0].samples[0].value == 0
    ch.registry.add("metrics_sock", Session(username="metrics_user", role="user"))
    assert metrics.connection_active.collect()[0].samples[0].value == 1
    ch.registry.reset()

def test_blocked_ips_active_reflects_detector_state():
    from datetime import datetime, timezone

    from tlsocket.server_side.logs_management import record_logs as rl

    rl.brute_force_detector.blocked_ips.clear()
    assert metrics.blocked_ips_active.collect()[0].samples[0].value == 0
    rl.brute_force_detector.blocked_ips["9.9.9.9"] = datetime.now(timezone.utc)
    assert metrics.blocked_ips_active.collect()[0].samples[0].value == 1
    rl.brute_force_detector.blocked_ips.clear()

def test_generate_latest_includes_all_metrics_names():
    output = generate_latest(metrics.METRICS_REGISTRY).decode("utf-8")
    for name in (
        "tlsocket_connections_total", "tlsocket_connections_active",
        "tlsocket_logins_total", "tlsocket_registrations_total",
        "tlsocket_messages_total", "tlsocket_blocked_ips_active",
    ):
        assert name in output