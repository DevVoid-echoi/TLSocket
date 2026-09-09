# TLSocket — Multi-Threaded TLS Chat System with RBAC & Security Logging

A multi-threaded client/server chat system built on Python's standard library
(`socket`, `ssl`, `threading`). The focus is a security-centric architecture:
TLS-encrypted transport, user authentication, Role-Based Access Control (RBAC),
real-time administrative control from the server console, structured security
logging, brute-force / connection-flood detection, and an offline log-analysis
module.

---

## Key Features

* **TLS transport** — every client/server connection is wrapped in `ssl` using
  the certificate in `certs/`.
* **Multi-threaded server** — one thread per client, with `threading.Lock`
  (`state_lock`, `ip_lock`) guarding shared state.
* **Authentication** — registration and login with salted SHA-256 password
  hashing; in-RAM session objects (`user_sessions`).
* **RBAC** — `admin`, `moderator`, `user` roles gate `/kick`, `/ban`, `/unban`,
  `/set` (see `auth/rbac.py`).
* **Server console** — the server operator can run `/set`, `/kick`, `/ban`,
  `/unban` directly from the server terminal; role changes are pushed to live
  client sessions without a reconnect.
* **Brute-force & flood protection** — repeated failed logins from an IP trigger
  an escalating temporary block (`security/brute_force_detection.py`); per-IP
  connection caps (`MAX_CONNECTIONS_PER_IP`) limit connection floods.
* **Structured logging** — operational events go to `logs/server.log`, security
  events to `logs/security.log`, brute-force alerts to `logs/alerts.log`.
* **Log analysis** — `log_parser/` streams a log file and reports login stats,
  error rate, top IPs, and suspicious / brute-force / DDoS indicators.

---

## Project Structure

```text
src/tlsocket/
├── config.py                     # HOST/PORT, limits, thresholds, runtime file paths
├── auth/
│   ├── authentication.py         # register / login / set_user_role, password hashing
│   ├── password.py               # (constants)
│   └── rbac.py                   # Permission + ROLES_PERMISSIONS, has_permission()
├── security/
│   ├── validation.py             # nickname / message / command validation
│   ├── brute_force_detection.py  # BruteForceDetector (stateful, persisted to data/)
│   └── logger.py                 # alert logger
├── client_side/
│   ├── client.py                 # client entry point (tlsocket-client)
│   └── client_management/
│       ├── connection.py         # receive / write loops, read_line
│       └── instructions.py       # role-aware help text
├── server_side/
│   ├── server.py                 # server entry point (tlsocket-server) + console thread
│   ├── handlers/
│   │   ├── client_handler.py     # client registry, broadcast, message loop, cleanup
│   │   ├── ban_handler.py        # ban-list file I/O
│   │   └── lock.py               # shared locks
│   └── logs_management/
│       └── record_logs.py        # log_event(), logger setup
└── log_parser/
    ├── main.py                   # CLI entry point (tlsocket-analyze)
    ├── parser.py                 # stream parser (generator)
    ├── analyzer.py               # aggregation
    └── models.py                 # LogRecord dataclass

tests/                            # brute-force / DDoS simulation scripts
data/                             # user.json, ban.txt, brute_force_state.json (gitignored)
certs/                            # server.crt / server.key (gitignored)
logs/                             # *.log (gitignored)
```

Runtime files are resolved relative to the current working directory. Override
with `TLSOCKET_DATA_DIR`, `TLSOCKET_LOG_DIR`, `TLSOCKET_CERT_DIR` (or
`TLSOCKET_CERT_FILE` / `TLSOCKET_KEY_FILE`), plus `TLSOCKET_HOST` /
`TLSOCKET_PORT`. See `.env.example`.

---

## Getting Started

### Prerequisites

* Python 3.10+ (developed on 3.12). Runtime is standard library only.
* A TLS key pair. To generate a self-signed pair for local use:

  ```bash
  mkdir -p certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost"
  ```

### Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Run the server

```bash
tlsocket-server
```

### Run a client (separate terminal)

```bash
tlsocket-client
```

### Analyze the logs

```bash
tlsocket-analyze -f security         # or: -f server
tlsocket-analyze -f security -o report.json
```

---

## Commands

### Server console (typed into the server terminal)

| Command | Effect |
| --- | --- |
| `/set <username> <role>` | Assign `admin` / `moderator` / `user` |
| `/kick <username>` | Disconnect an online user |
| `/ban <username>` | Add to ban list and disconnect if online |
| `/unban <username>` | Remove from ban list |

### Client chat room

| Command | Permission | Effect |
| --- | --- | --- |
| `/quit`, `/exit` | — | Leave the chat |
| `/kick <username>` | KICK | Remove a user |
| `/ban <username>` | BAN | Ban a user |
| `/unban <username>` | UNBAN | Lift a ban |
| `/set <username> <role>` | SET | Change a user's role |

Anything else typed is sent as a chat message.

---

## Log Format

```text
2026-08-27 15:00:15 INFO LOGIN_SUCCESS username=alice ip=127.0.0.1
2026-08-27 15:00:22 WARNING LOGIN_FAILED username=bob ip=127.0.0.1
2026-08-27 15:01:05 WARNING KICK username=spammer by=admin
```
