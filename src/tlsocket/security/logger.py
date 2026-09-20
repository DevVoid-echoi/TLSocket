import logging
from datetime import datetime, timezone

from tlsocket.logging_config import configure_logging

configure_logging()

security_logger = logging.getLogger("tlsocket.security")
alert_logger = logging.getLogger("tlsocket.alert")

def log_alert(ip: str, failed_attempts: int, window_seconds: int) -> None:
    fields = {"ip": ip, "failed_attempts": failed_attempts, "window_seconds": window_seconds}

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M%S")
    print(
        f"\033[91m{now_str} [ALERT] POSSIBLE BRUTE-FORCE ATTACK | "
        f"IP={ip} | FailedAttempts={failed_attempts} | Window={window_seconds}"
    )

    security_logger.warning("BRUTE_FORCE_ATTEMPT", extra=fields)
    alert_logger.warning("BRUTE_FORCE_ATTEMPT", extra=fields)