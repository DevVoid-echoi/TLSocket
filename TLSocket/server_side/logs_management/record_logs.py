import os
import sys
import logging
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
LOG_PARSER_DIR = os.path.join(BASE_DIR, "log_parser")
SECURITY_DIR = os.path.join(BASE_DIR, "security")

SERVER_LOGS_PATH = os.path.join(LOGS_DIR, "server.log")
SECURITY_LOGS_PATH = os.path.join(LOGS_DIR, "security.log")
TEST_LOGS_PATH = os.path.join(LOGS_DIR, "test.log")

from log_parser.models import LogRecord
from security.brute_force_detection import BruteForceDetector
from config import MAX_LOGIN_ATTEMPTS, LOGIN_WINDOW, BLOCK_DURATION

LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

formatter = logging.Formatter(LOG_FORMAT, datefmt = DATE_FORMAT)

log_lock = threading.Lock()

# --- Server Logger ---
server_logger =logging.getLogger("ServerLogger")
server_logger.setLevel(logging.INFO)

server_file_handler = logging.FileHandler(SERVER_LOGS_PATH, encoding='utf-8')
server_file_handler.setFormatter(formatter)
server_logger.addHandler(server_file_handler)

# --- Security Logger ---
security_logger = logging.getLogger("SecurityLogger")
security_logger.setLevel(logging.INFO)

security_file_handler = logging.FileHandler(SECURITY_LOGS_PATH, encoding='utf-8')
security_file_handler.setFormatter(formatter)
security_logger.addHandler(security_file_handler)

# --- Test Logger ---
test_logger = logging.getLogger("TestLogger")
test_logger.setLevel(logging.INFO)

test_file_handler = logging.FileHandler(TEST_LOGS_PATH, encoding="utf-8")
test_file_handler.setFormatter(formatter)
test_logger.addHandler(test_file_handler)

brute_force_detector = BruteForceDetector(
    max_attempts=MAX_LOGIN_ATTEMPTS,
    window_seconds=LOGIN_WINDOW,
    block_duration=BLOCK_DURATION)

# --- Log events ---
def log_event(event_type: str, username: str = "Unknown", ip: str = "N/A", extra_info: str = ""):
    msg = f"{event_type} username={username} "
    if ip!= "N/A":
        msg += f"ip={ip} "
    if extra_info:
        msg += f"{extra_info}"
    
    with log_lock:
        if event_type in ["USER_CONNECTED", "USER_DISCONNECTED", "CONNECTION_ERROR"]:
            server_logger.info(msg)
            server_file_handler.flush()
        elif event_type in ["LOGIN_SUCCESS", "REGISTER_SUCCESS"]:
            server_logger.info(msg)
            server_file_handler.flush()
            security_logger.info(msg)
            security_file_handler.flush()
        elif event_type in ["SET", "KICK", "BAN", "UNBAN"]:
            security_logger.info(msg)
            security_file_handler.flush()
        elif event_type in ["LOGIN_FAILED", "REGISTER_FAILED", "INVALID_COMMAND", "INVALID_FORMAT", "RATE_LIMIT_EXCEEDED", "CONNECTION_LIMIT_REACHED"]:
            security_logger.warning(msg)
            security_file_handler.flush()

    now = datetime.now()
    record=LogRecord(
        date=now.strftime("%Y-%m-%d"),
        time=now.strftime("%H:%M:%S"),
        event_type=event_type,
        level="WARNING" if event_type in ["LOGIN_FAILED", "REGISTER_FAILED", "INVALID_COMMAND", "INVALID_FORMAT", "RATE_LIMIT_EXCEEDED", "CONNECTION_LIMIT_REACHED"] else "INFO",
        username=username,
        ip=ip,
        extra_info=extra_info
    )

    brute_force_detector.process_record(record)

def log_test_event(event_type: str, username: str = "Unknown", ip: str = "N/A", extra_info: str = ""):
    msg = f"{event_type} username={username} "
    if ip!= "N/A":
        msg += f"ip={ip} "
    if extra_info:
        msg += f"{extra_info}"
    
    with log_lock:
        if event_type in ["USER_CONNECTED", "USER_DISCONNECTED", "CONNECTION_ERROR", "LOGIN_SUCCESS", "REGISTER_SUCCESS", "SET", "KICK", "BAN", "UNBAN"]:
            test_logger.info(msg)
            test_file_handler.flush()
        elif event_type in ["LOGIN_FAILED", "REGISTER_FAILED", "INVALID_COMMAND", "INVALID_FORMAT", "RATE_LIMIT_EXCEEDED"]:
            test_logger.warning(msg)
            test_file_handler.flush()

    now = datetime.now()
    record=LogRecord(
        date=now.strftime("%Y-%m-%d"),
        time=now.strftime("%H:%M:%S"),
        event_type=event_type,
        level="WARNING" if event_type in ["LOGIN_FAILED", "REGISTER_FAILED", "INVALID_COMMAND", "INVALID_FORMAT", "RATE_LIMIT_EXCEEDED"] else "INFO",
        username=username,
        ip=ip,
        extra_info=extra_info
    )

    brute_force_detector.process_record(record)
