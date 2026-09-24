# Changelog

All notable changes to this project are documented here.

## [Unreleased]
### Fixed
- Login race under concurrent logins (found by load test at ~250 clients): the `OK Connected` reply was written outside the send lock while broadcasters wrote to the same TLS socket (bad record MAC / client dropped), and the client was registered before `OK` was sent, so it could receive `joined` messages first.

### Added
- `benchmarks/loadtest.py` + `benchmarks/seed_users.py`: async load-test harness; rate limits overridable via `TLSOCKET_MAX_CONN_PER_IP` / `TLSOCKET_MAX_MSGS_PER_WINDOW`

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
