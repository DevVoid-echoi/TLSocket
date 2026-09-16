from tlsocket.config import MAX_LINE_LENGTH
from tlsocket.server_side.handlers.client_handler import read_line


class _FakeSocket:
    def __init__(self,chunks):
        self._chunks = list(chunks)

    def recv(self, bufsize):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

def test_read_line_assembles_across_chunks():
    sock = _FakeSocket([b"LOG", b"IN alice pw\nleftover"])
    line, buffer = read_line(sock, "")
    assert line == "LOGIN alice pw"
    assert buffer == "leftover"

def test_read_line_returns_none_on_eof():
    sock = _FakeSocket([b""])
    line, buffer = read_line(sock, "")
    assert line is None

def test_read_line_returns_none_on_socket_error():
    class _ErrSocket:
        def recv(self, bufsize):
            raise ConnectionResetError()

    line, buffer = read_line(_ErrSocket(), "")
    assert line is None

def test_read_line_stops_on_oversized_line_without_consuming_unbounded_data():
    call_count = {"n": 0}

    class _InfiniteSocket:
        def recv(self, bufsize):
            call_count["n"] += 1
            return b"a" * 1024

    line, buffer = read_line(_InfiniteSocket(), "")
    assert line is None
    assert call_count["n"] < 100
    assert len(buffer) > MAX_LINE_LENGTH