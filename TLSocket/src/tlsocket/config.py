"""Central configuration and runtime file locations.

Runtime files (user database, ban list, logs, TLS material) are resolved
relative to the current working directory by default, and can be redirected
with ``TLSOCKET_*`` environment variables.
"""

import os
from pathlib import Path


def _dir(env: str, default: str) -> Path:
    return Path(os.environ.get(env, default)).expanduser()


HOST = os.environ.get("TLSOCKET_HOST", "0.0.0.0")  # bind/connect address
PORT = int(os.environ.get("TLSOCKET_PORT", "9999"))

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60
BLOCK_DURATION = 10

MAX_NICKNAME_LENGTH = 20
MIN_NICKNAME_LENGTH = 1
MAX_MESSAGE_LENGTH = 1000

MAX_CONNECTIONS_PER_IP = 5

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
