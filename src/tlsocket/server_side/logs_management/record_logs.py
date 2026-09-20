import logging
from datetime import datetime, timezone

from tlsocket.config import (
    BLOCK_DURATION,
    LOGIN_WINDOW,
    MAX_LOGIN_ATTEMPTS,
)
from tlsocket.log_parser.models import LogRecord
from tlsocket.logging_config import configure_logging
from tlsocket.security.brute_force_detection import BruteForceDetector

configure_logging()

server_logger = logging.getLogger("tlsocket.server")
security_logger = logging.getLogger("tlsocket.security")
test_logger = logging.getLogger("tlsocket.test")

brute_force_detector = BruteForceDetector(
    max_attempts=MAX_LOGIN_ATTEMPTS,
    window_seconds=LOGIN_WINDOW,
    block_duration=BLOCK_DURATION
)

# --- Log events ---
SERVER_ONLY = frozenset({"USER_CONNECTED", "USER_DISCONNECTED", "CONNECTION_ERROR"})
SERVER_AND_SECURITY = frozenset({"LOGIN_SUCCESS", "REGISTER_SUCCESS"})
SECURITY_ONLY = frozenset({"SET", "KICK", "BAN", "UNBAN"})
WARNING_EVENTS = frozenset({
    "LOGIN_FAILED", "REGISTER_FAILED", "INVALID_COMMAND", "INVALID_FORMAT",
    "RATE_LIMIT_EXCEEDED", "CONNECTION_LIMIT_REACHED"
})

def _emit(logger: logging.Logger, event: str, username: str, ip: str, extra_info: str):
    level = logging.WARNING if event in WARNING_EVENTS else logging.INFO
    fields = {"username": username}
    if ip != "N/A":
        fields["ip"] = ip
    if extra_info:
        fields["extra_info"] = extra_info
    logger.log(level, event, extra=fields)

def _feed_detector(event: str, username: str, ip: str, extra_info: str) -> None:
    brute_force_detector.process_record(LogRecord(
        timestamp=datetime.now(timezone.utc),
        event_type=event,
        level="WARNING" if event in WARNING_EVENTS else "INFO",
        username=username,
        ip=ip,
        extra_info=extra_info
    ))

def log_event(event_type: str, username: str = "unknown", ip: str = "N/A", extra_info: str = ""):
    if event_type in SERVER_ONLY:
        _emit(server_logger, event_type, username, ip, extra_info)
    elif event_type in SERVER_AND_SECURITY:
        _emit(server_logger, event_type, username, ip, extra_info)
        _emit(security_logger, event_type, username, ip, extra_info)
    elif event_type in SECURITY_ONLY or event_type in WARNING_EVENTS:
        _emit(security_logger, event_type, username, ip, extra_info)
    _feed_detector(event_type, username, ip, extra_info)

def log_test_event(event_type: str, username: str = "unknown", ip: str = "N/A", extra_info: str = ""):
    _emit(test_logger, event_type, username, ip, extra_info)
    _feed_detector(event_type, username, ip, extra_info)
