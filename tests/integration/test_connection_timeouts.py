import socket

from tlsocket.server_side import server as sv


def test_silent_connection_is_dropped_after_handshake_timeout(running_server, monkeypatch):
    monkeypatch.setattr(sv, "HANDSHAKE_TIMEOUT_SECONDS", 0.5)

    port = running_server
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    data = raw.recv(10)
    assert data == b""

def test_connection_with_no_login_is_dropped_after_auth_timeout(running_server, monkeypatch, make_client):
    monkeypatch.setattr(sv, "AUTH_TIMEOUT_SECONDS", 0.5)

    client = make_client()
    line = client.recv_line()
    assert line is None