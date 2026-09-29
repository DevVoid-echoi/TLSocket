from hypothesis import given
from hypothesis import strategies as st

from tlsocket.client_side.client_management.connection import read_line
from tlsocket.config import MAX_LINE_LENGTH


class FakeSock:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""

PIECES = st.sampled_from([b"a" * 4096, b"a" * 1000, b"xyz", b"\n", b"b\n", b"\xff\xfe"])

@given(st.lists(PIECES, min_size=1, max_size=8))
def test_read_line_respects_max_length(chunks):
    line, _ = read_line(FakeSock(chunks), b"")
    assert line is None or len(line) <= MAX_LINE_LENGTH

def test_read_line_stops_on_oversized_line_without_consuming_unbounded_data():
    call_count = {"n": 0}

    class _InfiniteSocket:
        def recv(self, bufsize):
            call_count["n"] += 1
            return b"a" * 1024

    line, buffer = read_line(_InfiniteSocket(), b"")
    assert line is None
    assert call_count["n"] < 100
    assert len(buffer) > MAX_LINE_LENGTH