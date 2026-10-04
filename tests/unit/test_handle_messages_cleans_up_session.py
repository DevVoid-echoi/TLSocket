import pytest

from tlsocket.server_side.client_registry import Session
from tlsocket.server_side.handlers import client_handler as ch


def test_handle_messages_cleans_up_session_on_unexpected_exception(monkeypatch):
    class _Socket:
        def __init__(self, lines):
            self._lines = [line.encode() + b"\n" for line in lines]

        def recv(self, n):
            return self._lines.pop(0) if self._lines else b""

        def close(self):
            pass

    def _boom(name):
        raise OSError("disk full")
    monkeypatch.setattr(ch, "add_ban", _boom)

    sock = _Socket(["BAN bob"])
    ch.registry.reset()
    ch.registry.add(sock, Session(username="alice", role="admin"))

    with pytest.raises(OSError):
        ch.handle_messages(sock)

    assert ch.registry.get_session(sock) is None
        