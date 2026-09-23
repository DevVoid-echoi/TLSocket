import json

from tlsocket.config import SECURITY_LOG, SERVER_LOG
from tlsocket.server_side.logs_management.record_logs import log_event


def _find(path, username):
    for line in reversed(path.read_text(encoding="utf-8").splitlines()):
        entry = json.loads(line)
        if entry.get("username") == username:
            return entry
    raise AssertionError(f"Found 0 log of {username} in {path}")

def test_log_event_writes_json_line():
    log_event("USER_CONNECTED", username="user_a", ip="9.9.9.1")
    entry = _find(SERVER_LOG, "user_a")
    assert entry["event"] == "USER_CONNECTED"
    assert entry["level"] == "INFO"
    assert entry["ip"] == "9.9.9.1"
    assert entry["ts"].endswith("+00:00")

def test_warning_events_are_warning_level_in_security_log():
    log_event("LOGIN_FAILED", username="user_a", ip="9.9.9.2", extra_info="reason=BANNED")
    entry = _find(SECURITY_LOG, "user_a")
    assert entry["level"] == "WARNING"
    assert entry["extra_info"] == "reason=BANNED"

def test_ip_field_omitted_when_not_available():
    log_event("USER_DISCONNECTED", username="user_a")
    assert "ip" not in _find(SERVER_LOG, "user_a")

def test_login_success_goes_to_server_and_security_logs():
    log_event("LOGIN_SUCCESS", username="user_a", ip="9.9.9.4")
    assert _find(SERVER_LOG, "user_a")["event"] == "LOGIN_SUCCESS"
    assert _find(SECURITY_LOG, "user_a")["event"] == "LOGIN_SUCCESS"
