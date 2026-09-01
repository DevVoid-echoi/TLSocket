```markdown
# Multi-Threaded TCP Chat System with RBAC & Security Logging

A multi-threaded Client-Server chat system built using Python Pure-Sockets. The project focuses on a security-centric architecture featuring user authentication, Role-Based Access Control (RBAC), real-time administrative management via Server Console, production-ready security logging, and an integrated log parsing module for security analysis.

---

## 🌟 Key Features

* **Multi-Threaded Architecture**: Handles concurrent client connections using `socket` and `threading` with thread-safe synchronization locks (`state_lock`).
* **Authentication & Session Management**: Secure user registration and login with password hashing (Bcrypt/SHA-256) and active session management (`user_sessions`).
* **Role-Based Access Control (RBAC)**: Flexible command execution rights (`/kick`, `/ban`, `/unban`) governed by user roles (`admin`, `moderator`, `user`).
* **Server Console Control**: Allows administrators to dynamically assign roles (`/set <username> <role>`) directly from the server terminal in real time.
* **Real-time Session Synchronization**: Automatically syncs role updates from persistent storage (`user.json`) directly to active client RAM sessions without requiring a reconnect.
* **Security & System Logging**: Separates operational logs (`server.log`) and security audit logs (`security.log`) with automatic disk flushing (`flush`). Passwords are never stored in plain-text.
* **Log Parser & Analytics Engine**: Includes a generator-based (`yield`) stream parser and analytics engine (`log_parser`) to parse security events, track failed login attempts, calculate error rates, and identify top requesting IP addresses.

---

## 📁 Project Structure

```text
tcp_chat_room/
├── auth/
│   ├── authentication.py    # Handles login, registration, password hashing, set_user_role
│   ├── password.py          # Password hashing and verification utilities
│   └── rbac.py              # Role & Permission definitions (ADMIN, MODERATOR, USER)
├── client_side/
│   ├── client_management/    
│   │   ├── connection.py    # Client-side TCP socket connection management
│   │   └── instruction.py   # Dynamic command line instructions based on user role
│   └── client.py            # Client entry point
├── data/
│   ├── ban.txt              # Database for banned user accounts
│   └── user.json            # Database for user credentials & RBAC roles
├── log_parser/              # Security Log Parsing & Analytics Module
│   └── src/
│       ├── analyzer.py      # Aggregates log metrics (failed logins, error rates, top IPs)
│       ├── main.py          # Entry point for running log analysis reports
│       ├── models.py        # LogRecord dataclass definition
│       └── parser.py        # Stream-based log parser using generator-based yield
├── logs/
│   ├── security.log         # Security events: logins, permission violations, KICK/BAN/UNBAN
│   └── server.log           # Operational logs: connections, disconnections, system events
├── server_side/
│   ├── client_management/
│   │   ├── actions.py       # Message routing and command execution (KICK, BAN, UNBAN)
│   │   ├── ban_handler.py   # Reads and writes banned user lists
│   │   └── lock.py          # Thread lock preventing race conditions (state_lock)
│   ├── logs_management/
│   │   └── record_logs.py   # Log initialization and recording module
│   └── server.py            # Main entry point for TCP Server & Console Thread
├── config.py                # Configuration parameters: PORT, HOST, and file paths
└── README.md                # Project documentation

```

---

## 🛠️ Commands & Syntax

### 1. Server Console (Executed directly from the Server Terminal)

* `/set <username> <role>`: Assigns a new role to a user (`admin`, `moderator`, `user`).

### 2. Client Chat Room

* `/quit` or `/exit`: Disconnects and exits the chat room.
* `/kick <username>`: Removes a user from the chat room *(Requires KICK permission)*.
* `/ban <username>`: Permanently bans a user from joining *(Requires BAN permission)*.
* `/unban <username>`: Lifts a ban for a specified user *(Requires UNBAN permission)*.

---

## 🚀 Getting Started

### Prerequisites

* **Python 3.10+** (Built using Python standard libraries; no external package dependencies required).

### Step 1: Launch the Server

Open a terminal in the project root directory (`tcp_chat_room`):

```bash
python3 server_side/server.py

```

### Step 2: Launch the Client

Open another terminal window and run:

```bash
python3 client_side/client.py

```

### Step 3: Run Security Log Analysis

To parse and generate a statistical report from `logs/security.log`, execute:

```bash
python3 log_parser/src/main.py logs/security.log

```

---

## 📝 Security Log & Parser Output Format

### 1. Log Event Format (`logs/security.log`)

```text
2026-08-27 15:00:10 INFO USER_CONNECTED username=N/A ip=127.0.0.1
2026-08-27 15:00:15 INFO LOGIN_SUCCESS username=alice ip=127.0.0.1
2026-08-27 15:00:22 WARNING LOGIN_FAILED username=bob ip=127.0.0.1
2026-08-27 15:01:05 WARNING KICK username=spammer by=admin
2026-08-27 15:01:10 WARNING BAN username=spammer by=admin

```

### 2. Log Parser Analytics Report (`log_parser`)

```json
{
  "total_requests": 5,
  "successful_logins": 1,
  "failed_logins": 1,
  "kicked_users": 1,
  "banned_users": 1,
  "error_count": 0,
  "error_rate": 0.0,
  "top_5_IPs": [
    ["127.0.0.1", 2]
  ]
}

```

```

```