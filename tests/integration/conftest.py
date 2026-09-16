import socket
import ssl

import pytest

from tlsocket.config import CERT_FILE, KEY_FILE

pytestmark = pytest.mark.skipif(
    not (CERT_FILE.exists() and KEY_FILE.exists()),
    reason="Cần openssl để tạo TLS cert test (xem cảnh báo lúc collection ở tests/conftest.py)",
)

@pytest.fixture
def running_server(tmp_path, monkeypatch):
    from tlsocket.auth import authentication as auth

    users_file = tmp_path / "user.json"
    ban_file = tmp_path / "ban.txt"
    monkeypatch.setattr(auth, "USERS_FILE", users_file)
    monkeypatch.setattr(auth, "BAN_FILE", ban_file)

    from tlsocket.server_side import server as srv
    from tlsocket.server_side.handlers import client_handler as ch
    from tlsocket.server_side.logs_management import record_logs as rl
    ch.clients.clear()
    ch.nicknames.clear()
    ch.user_sessions.clear()
    ch.pending_logins.clear()
    ch.ip_connection_counts.clear()
    ch.client_ips.clear()
    rl.brute_force_detector.blocked_ips.clear()
    rl.brute_force_detector.violation_count.clear()
    rl.brute_force_detector.failed_attempts_history.clear()
    srv.register_limiter.reset()

    thread, sock, port = srv.create_server(host="127.0.0.1", port=0)

    yield port

    sock.close()
    thread.join(timeout=2)

class Connection:
    """Bọc quanh 1 client TLS thật: gửi/nhận theo dòng, tự giữ buffer dư
    giữa các lần gọi recv_line() - mô phỏng đúng khung giao thức của server."""
    def __init__(self, sock):
        self.sock = sock
        self._buffer = ""

    def send(self, text):
        self.sock.sendall((text + "\n").encode("utf-8"))

    def recv_line(self):
        while "\n" not in self._buffer:
            chunk = self.sock.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                return None
            self._buffer += chunk
        line, self._buffer = self._buffer.split("\n", 1)
        return line.strip()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

@pytest.fixture
def make_client(running_server):
    """Factory: gọi make_client() để tạo 1 client TLS thật kết nối vào
    server test. Tất cả client tạo ra được tự đóng khi test kết thúc."""
    port = running_server
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(CERT_FILE))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    opened = []

    def _connect():
        raw = socket.create_connection(("127.0.0.1", port), timeout = 5)
        tls_sock = ctx.wrap_socket(raw, server_hostname="localhost")
        tls_sock.settimeout(5)
        conn = Connection(tls_sock)
        opened.append(conn)
        return conn

    yield _connect

    for c in opened:
        c.close()