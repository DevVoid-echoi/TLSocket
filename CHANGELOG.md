# Changelog

All notable changes to this project are documented here.

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
