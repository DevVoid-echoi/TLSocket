# Changelog

All notable changes to this project are documented here.

## [1.1.0] - 2026-09-29
### Security
- Chat messages could carry ANSI/terminal control sequences (`validate_message` only checked for NUL bytes) — now rejects all Unicode control characters.
- A failed TLS handshake freed a per-IP connection slot it never reserved, letting attackers bypass `MAX_CONNECTIONS_PER_IP` one connection at a time.

### Fixed
- Login race under concurrent logins (found by load test at ~250 clients): the `OK Connected` reply was written outside the send lock while broadcasters wrote to the same TLS socket (bad record MAC / client dropped), and the client was registered before `OK` was sent, so it could receive `joined` messages first.
- `read_line()` decoded each `recv()` chunk independently, corrupting multi-byte UTF-8 characters split across reads, and only soft-enforced `MAX_LINE_LENGTH` (bypassable by controlling chunk boundaries).

### Added
- `benchmarks/loadtest.py` + `benchmarks/seed_users.py`: async load-test harness; rate limits overridable via `TLSOCKET_MAX_CONN_PER_IP` / `TLSOCKET_MAX_MSGS_PER_WINDOW`
- `docs/BENCHMARKS.md`: measured thread-per-client throughput/latency/memory at 250/500/1000 concurrent clients
- Hypothesis-based property and fuzz tests for the protocol parser, input validation, line framing, the per-IP connection registry (stateful test), and wire-level fuzzing against a live server

## [1.0.0] - 2026-09-23
### Added
- TLS chat server with per-client threading, RBAC (`admin`/`moderator`/`user`)
- Argon2id password hashing with automatic migration from legacy SHA-256 hashes
- Brute-force detection and connection-flood protection (per-IP caps, sliding-window rate limits)
- Structured JSON-lines logging (`server.log`, `security.log`, `alerts.log`)
- Log analyzer CLI (`tlsocket-analyze`) — analytics, `--since`, `--follow`, JSON/table output
- Prometheus metrics + Grafana dashboard, Docker Compose stack
- Protocol-level `PING`/`PONG` health check
- Architecture and decision-record documentation (`docs/ARCHITECTURE.md`, `docs/DECISIONS.md`)
