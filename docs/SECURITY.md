# Security

TLSocket is a learning/portfolio project, not a production messaging system —
but it's built with a security-first mindset, and this document is meant to
be read that way: what each threat is, what actually mitigates it today, and
where the honest limits are. Treating the gaps as a checklist to close, not
something to hide, is the point.

## Threat model

### 1. Brute-force login guessing

**Threat**: an attacker repeatedly guesses passwords against `LOGIN`.

**Mitigation**: [`security/brute_force_detection.py`](../src/tlsocket/security/brute_force_detection.py)
tracks `LOGIN_FAILED` events per IP in a sliding window
(`LOGIN_WINDOW` = 60s). Once `MAX_LOGIN_ATTEMPTS` (5) failures land inside
the window, the IP is blocked for `BLOCK_DURATION` (10s), escalating on
repeat offenses (×5, ×30, ×1440 the base duration) — state persists to disk
across restarts (`data/brute_force_state.json`).

**Limits**:
- Purely IP-based. A distributed attacker (botnet, many IPs) trivially
  bypasses per-IP blocking — this needs a higher-level control (WAF, CDN,
  fail2ban-style cross-service correlation) that's out of scope for a single
  process.
- No notification to the account owner when their account is targeted.

### 2. Connection / request flooding (DoS)

**Threat**: an attacker opens many connections, spams `REGISTER`, spams chat
messages, or sends an unbounded line to exhaust memory.

**Mitigation**, layered:
- `MAX_CONNECTIONS_PER_IP` (5 concurrent) — [`client_handler.py`](../src/tlsocket/server_side/handlers/client_handler.py)`.accept_new_client()`.
- `REGISTER` rate-limited per IP (`MAX_REGISTER_ATTEMPTS` / `REGISTER_WINDOW`)
  via [`security/rate_limiter.py`](../src/tlsocket/security/rate_limiter.py)`.SlidingWindowLimiter`
  — counts every attempt (not just failures), since account-creation spam is
  the threat, not credential guessing.
- Chat messages rate-limited per connection (`MAX_MESSAGES_PER_WINDOW` /
  `MESSAGE_RATE_WINDOW`), same `SlidingWindowLimiter`.
- `read_line()`'s buffer is capped at `MAX_LINE_LENGTH` — a peer that never
  sends `\n` gets disconnected once its unterminated line exceeds the cap,
  instead of growing the server's memory without bound.

**Limits**:
- Nothing here stops a raw TCP SYN flood or rapid connect/disconnect
  cycling below the application layer — that's a firewall/reverse-proxy
  concern, not something a Python socket server can defend against alone.
- `SlidingWindowLimiter` state is in-memory only (not persisted like
  brute-force state), so it resets on restart — acceptable for its purpose
  (short-lived flood damping, not long-term banning).

### 3. Man-in-the-middle / eavesdropping

**Threat**: an attacker on the network path reads or tampers with
credentials and chat content in transit.

**Mitigation**: every connection is wrapped in TLS
(`ssl.PROTOCOL_TLS_SERVER` / `PROTOCOL_TLS_CLIENT`), `verify_mode =
CERT_REQUIRED`, and — as of this hardening pass — `check_hostname = True`
with a certificate carrying the correct `subjectAltName` (`localhost`,
`127.0.0.1`; see [`scripts/gen_certs.sh`](../scripts/gen_certs.sh)). Before
this, `check_hostname` was `False` and the shipped cert had no SAN at all,
so hostname verification could never meaningfully have passed — TLS was
encrypting the channel but not actually authenticating which server was on
the other end.

**Limits**:
- The shipped certificate is **self-signed, for local development only**.
  It is not in any trusted root store, so anything other than a client
  configured with this exact CA (as this project's client is) will reject
  it. **Production deployments must use a certificate from a real CA**
  (e.g. [Let's Encrypt](https://letsencrypt.org/)) — see the README.
- No certificate pinning beyond `load_verify_locations` trusting the one
  configured cert; no cipher-suite/TLS-version pinning beyond the `ssl`
  module's own defaults.

### 4. Injection via nickname / chat / commands

**Threat**: a hostile nickname or message forges protocol lines, breaks
framing, or manipulates other clients.

**Mitigation**: [`security/validation.py`](../src/tlsocket/security/validation.py):
- `validate_nickname`: alphanumeric + underscore only, length-bounded,
  rejects `\n`/`\r`/NUL — the framing characters an attacker would need to
  inject a fake protocol line via a nickname.
- `validate_message`: length-bounded, rejects NUL.
- `parse_and_validate_command`: strict argument-count checking for
  `KICK`/`BAN`/`UNBAN`/`SET` before they're acted on.
- There's no database and no dynamic code execution reachable from user
  input, so classic SQL/command injection has no vector here — the realistic
  injection risk in a line-based text protocol is framing injection (forging
  a second protocol line via unescaped input), which the character rejection
  above addresses.
- Authorization for privileged commands (`KICK`/`BAN`/`UNBAN`/`SET`) is
  enforced server-side via [`auth/rbac.py`](../src/tlsocket/auth/rbac.py)`.has_permission()`,
  not just hidden client-side — a modified/hostile client gains nothing by
  sending a command its role doesn't have.

### 5. Session fixation

**Threat** (classically): an attacker pre-sets a victim's session
identifier before login, then reuses that known identifier to hijack the
authenticated session.

**Why it doesn't apply here the way it does to a web app**: there is no
session token, cookie, or identifier negotiated or transmitted at all. A
"session" (`user_sessions[client]` in
[`client_handler.py`](../src/tlsocket/server_side/handlers/client_handler.py))
is just an in-memory dict keyed by the live TCP+TLS socket object itself —
it comes into existence only after a successful `LOGIN` on *that specific*
connection, and is destroyed the moment the socket closes. There is nothing
an attacker could pre-set or hand to a victim to fix in advance. The
username-uniqueness check (`pending_logins`/`nicknames`, rejecting a second
concurrent `LOGIN` for the same account with `ALREADY_LOGGED_IN`) closes the
adjacent concern of two connections racing to claim the same identity.

### 6. Password storage

**Mitigation**: [`auth/authentication.py`](../src/tlsocket/auth/authentication.py)
hashes with **Argon2id** (`argon2-cffi`), a random salt generated and
embedded per hash — two users with the same password no longer produce the
same stored hash. Accounts created before this change (SHA-256 + one
hard-coded salt shared by every user) are verified with
`hmac.compare_digest` (constant-time, avoiding a timing side-channel on
password comparison) and **transparently migrated** to Argon2id on their
next successful login (`needs_rehash()` in the same file) — no forced
password reset.

## Known gaps (tracked, not fixed yet)

Being upfront about what's still open, rather than presenting the above as
a finished state:

- **Partial write-lock coverage**: a `send_lock` (added after an
  integration test caught it corrupting a live TLS session) serializes
  concurrent writes to the same client socket in `broadcast()` and
  `kick_user()`'s personal message. Several other direct
  `client.send()`/`sendall()` call sites (auth `OK`/`ERR` responses in
  `server.py`, permission-denied replies and the "commands unlocked"
  notice in `client_handler.py`) are not yet guarded the same way — see the
  comment above `send_lock`'s definition in
  [`server_side/handlers/lock.py`](../src/tlsocket/server_side/handlers/lock.py)
  for the current list.
- **No session revocation / forced logout** beyond `/ban` (which kicks and
  blocks future logins) — there's no way to invalidate one specific live
  session (e.g. a stolen/compromised client) without banning the account
  outright.
- **IP-based rate limiting only** — see the brute-force and flooding
  sections above; a motivated distributed attacker isn't meaningfully
  slowed down by any of it.

## Reporting a vulnerability

This is a personal/portfolio project without a formal disclosure process.
If you find a security issue, please open a GitHub issue on this
repository describing it.
