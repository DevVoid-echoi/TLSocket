# ADR-001: Thread-per-client instead of asyncio

**Context:** Need to handle multiple clients concurrently for a chat server.
**Decision:** Use one `threading.Thread` per client (accept loop + message loop), with shared state protected by `threading.Lock`.
**Trade-off:** Simpler and easier to debug than asyncio (no async/await threading through the whole call stack, easy to integrate synchronous libraries like `ssl`/`argon2-cffi`). Trade-off: higher RAM usage at a scale of thousands of connections (each thread ~8MB stack) — asyncio scales better, but in exchange the entire codebase (I/O, hashing, file access) would need to be written non-blocking.

# ADR-002: Argon2id instead of bcrypt/PBKDF2

**Context:** Need secure password hashing.
**Decision:** `argon2-cffi`, with backward compatibility for the old SHA-256+salt hashes via `_is_legacy_hash()`/`needs_rehash()` ([authentication.py:53-63](src/tlsocket/auth/authentication.py#L53-L63)).
**Trade-off:** Argon2id won the Password Hashing Competition and resists GPU-cracking better than bcrypt (tunable memory cost). Trade-off: slower than bcrypt on weaker hardware, and `time_cost`/`memory_cost` need tuning for the actual server.

# ADR-003: Custom TCP text protocol instead of HTTP/WebSocket

**Context:** Need a message protocol between client and server.
**Decision:** A custom line-based text protocol (`protocol.py`, commands like `LOGIN`/`MSG`/`ERR ...`).
**Trade-off:** No external library needed, easy to debug with `nc`/telnet (though TLS here means going through `openssl s_client` instead), and it's a good exercise in designing your own framing (`read_line`, `MAX_LINE_LENGTH`). Trade-off: loses compatibility with existing HTTP tooling (browsers, proxies, L7 load balancers), and all the validation/framing that HTTP/WebSocket already standardizes has to be handled manually.
