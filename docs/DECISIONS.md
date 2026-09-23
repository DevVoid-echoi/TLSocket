# ADR-001: Thread-per-client thay vì asyncio

**Context:** Cần xử lý nhiều client đồng thời cho 1 chat server.
**Decision:** Dùng `threading.Thread` mỗi client (accept loop + message loop), state dùng chung qua `threading.Lock`.
**Trade-off:** Đơn giản, dễ debug hơn asyncio (không cần async/await xuyên suốt callstack, dễ tích hợp thư viện đồng bộ như `ssl`/`argon2-cffi`). Đánh đổi: tốn RAM hơn ở quy mô hàng nghìn kết nối (mỗi thread ~8MB stack) — asyncio scale tốt hơn nhưng đổi lại toàn bộ codebase (io, hash, file) phải viết non-blocking.

# ADR-002: Argon2id thay vì bcrypt/PBKDF2

**Context:** Cần hash mật khẩu an toàn.
**Decision:** `argon2-cffi`, giữ tương thích ngược với hash SHA-256+salt cũ qua `_is_legacy_hash()`/`needs_rehash()` ([authentication.py:53-63](src/tlsocket/auth/authentication.py#L53-L63)).
**Trade-off:** Argon2id thắng giải Password Hashing Competition, chống GPU-cracking tốt hơn bcrypt (tunable memory cost). Đánh đổi: chậm hơn bcrypt trên hardware yếu, cần tune `time_cost`/`memory_cost` theo server thực tế.

# ADR-003: TCP text protocol tự chế thay vì HTTP/WebSocket

**Context:** Cần giao thức truyền message giữa client/server.
**Decision:** Line-based text protocol tự định nghĩa (`protocol.py`, lệnh `LOGIN`/`MSG`/`ERR ...`).
**Trade-off:** Không cần thư viện ngoài, dễ debug bằng `nc`/telnet (dù ở đây có TLS nên phải qua `openssl s_client`), học được cách tự thiết kế framing (`read_line`, `MAX_LINE_LENGTH`). Đánh đổi: mất tương thích với tooling HTTP có sẵn (browser, proxy, load balancer L7), phải tự lo hết validation/framing mà HTTP/WebSocket đã chuẩn hoá.
