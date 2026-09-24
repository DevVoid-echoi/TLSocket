"""Central configuration and runtime file locations.

Runtime files (user database, ban list, logs, TLS material) live under the
project root by default - NOT the current working directory, so running the
server from any folder (e.g. an IDE "Run" button whose cwd is the file's own
directory) can't scatter stray logs/, data/, certs/ directories around.
They can be redirected with ``TLSOCKET_*`` environment variables.
"""

import os
from pathlib import Path


def _project_root() -> Path:
    """Project root of a source checkout (src/ layout: this file is
    <root>/src/tlsocket/config.py, identified by the pyproject.toml two
    levels up). For a regular installed package there is no such file next to
    site-packages, so fall back to the current working directory."""
    root = Path(__file__).resolve().parents[2]
    return root if (root / "pyproject.toml").exists() else Path.cwd()


_ROOT = _project_root()


def _dir(env: str, default: str) -> Path:
    override = os.environ.get(env)
    return Path(override).expanduser() if override else _ROOT / default


HOST = os.environ.get("TLSOCKET_HOST", "0.0.0.0")  # nosec B104 - server cố ý bind mọi interface theo mặc định; production nên giới hạn qua TLSOCKET_HOST/firewall
PORT = int(os.environ.get("TLSOCKET_PORT", "9999"))

CLIENT_HOST = os.environ.get("TLSOCKET_CLIENT_HOST", "localhost")

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60
BLOCK_DURATION = 10

MAX_REGISTER_ATTEMPTS = 5
REGISTER_WINDOW = 60

MAX_NICKNAME_LENGTH = 20
MIN_NICKNAME_LENGTH = 1
MAX_MESSAGE_LENGTH = 1000
MAX_MESSAGES_PER_WINDOW = int(os.environ.get("TLSOCKET_MAX_MSGS_PER_WINDOW", "10"))
MESSAGE_RATE_WINDOW = 10
MAX_LINE_LENGTH = 4096

MAX_CONNECTIONS_PER_IP = int(os.environ.get("TLSOCKET_MAX_CONN_PER_IP", "5"))

# --- Runtime file locations -------------------------------------------------

DATA_DIR = _dir("TLSOCKET_DATA_DIR", "data")
LOG_DIR = _dir("TLSOCKET_LOG_DIR", "logs")
CERT_DIR = _dir("TLSOCKET_CERT_DIR", "certs")

USERS_FILE = DATA_DIR / "user.json"
BAN_FILE = DATA_DIR / "ban.txt"
BRUTE_FORCE_STATE_FILE = DATA_DIR / "brute_force_state.json"

SERVER_LOG = LOG_DIR / "server.log"
SECURITY_LOG = LOG_DIR / "security.log"
TEST_LOG = LOG_DIR / "test.log"
ALERT_LOG = LOG_DIR / "alerts.log"

CERT_FILE = Path(os.environ.get("TLSOCKET_CERT_FILE") or CERT_DIR / "server.crt")
KEY_FILE = Path(os.environ.get("TLSOCKET_KEY_FILE") or CERT_DIR / "server.key")

METRICS_PORT = int(os.environ.get("TLSOCKET_METRICS_PORT", "9100"))