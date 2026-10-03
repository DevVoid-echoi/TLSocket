import pytest

from tlsocket.server_side.client_registry import Session
from tlsocket.server_side.handlers import client_handler as ch


def test_handle_messages_cleans_up_session_on_send_exception():
    class _ExplodingSocket:
        def __init__(self, lines):
            self._lines = [line.encode() + b"\n" for line in lines]

        def recv(self, n):
            return self._lines.pop(0) if self._lines else b""

        def send(self, data):
            raise OSError("Bad file descriptor")

        def close(self):
            pass

    sock = _ExplodingSocket(["x" * 2001])
    ch.registry.reset()
    ch.registry.add(sock, Session(username="alice", role="user"))

    with pytest.raises(OSError):
        ch.handle_messages(sock)

    assert ch.registry.get_session(sock) is None
    assert ch.registry.by_name("alice") is None
        