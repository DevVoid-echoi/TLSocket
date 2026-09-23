import logging.config
from pathlib import Path
from typing import Any

from tlsocket.config import ALERT_LOG, LOG_DIR, SECURITY_LOG, SERVER_LOG, TEST_LOG

_configured = False

def build_config() -> dict[str, Any]:
    def file_handler(path: Path) -> dict[str, Any]:
        return {
            "class": "logging.FileHandler",
            "filename": str(path),
            "encoding": "utf-8",
            "formatter": "json",
        }

    def logger(handler: str, level: str) -> dict[str, Any]:
        return {"handlers": [handler], "level": level, "propagate": False}

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": "pythonjsonlogger.json.JsonFormatter",
                "fmt": "%(levelname)s %(message)s",
                "rename_fields": {"levelname": "level", "message": "event"},
                "timestamp": "ts",
            },
        },
        "handlers": {
            "server": file_handler(SERVER_LOG),
            "security": file_handler(SECURITY_LOG),
            "alert": file_handler(ALERT_LOG),
            "test": file_handler(TEST_LOG),
        },
        "loggers": {
            "tlsocket.server": logger("server", "INFO"),
            "tlsocket.security": logger("security", "INFO"),
            "tlsocket.alert": logger("alert", "WARNING"),
            "tlsocket.test": logger("test", "INFO"),
        }, 
    }

def configure_logging() -> None:
    global _configured
    if _configured:
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.config.dictConfig(build_config())
    _configured = True