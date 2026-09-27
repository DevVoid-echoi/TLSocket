import re
import unicodedata

from hypothesis import given
from hypothesis import strategies as st

from tlsocket.config import MAX_LINE_LENGTH
from tlsocket.protocol import Command, parse_command
from tlsocket.security.validation import (
    parse_and_validate_command,
    validate_message,
    validate_nickname,
)
from tlsocket.server_side.handlers.client_handler import read_line


class FakeSock:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""


@given(st.text())
def test_parse_command_never_raises(line):
    cmd, _ = parse_command(line)
    assert cmd is None or isinstance(cmd, Command)

@given(st.text())
def test_command_arg_counts_when_ok(line):
    cmd, args, status = parse_and_validate_command(line)
    if status == "OK" and cmd in ("KICK", "BAN", "UNBAN"):
        assert len(args) == 1
    if status == "OK" and cmd == "SET":
        assert len(args) == 2

@given(st.text())
def test_validate_nickname_invariants(n):
    ok, _ = validate_nickname(n)
    if ok:
        s = n.strip()
        assert 1 <= len(s) <= 20 and re.fullmatch(r"[a-zA-Z0-9_]+", s) and s!="admin"

@given(st.text())
def test_accepted_message_has_no_control_chars(m):
    ok, _ = validate_message(m)
    if ok:
        assert not any(unicodedata.category(c) == "Cc" for c in m)

PIECES = st.sampled_from([b"a" * 4096, b"a" * 1000, b"xyz", b"\n", b"b\n", b"\xff\xfe"])


@given(st.lists(PIECES, min_size=1, max_size=8))
def test_read_line_respects_max_length(chunks):
    line, _ = read_line(FakeSock(chunks), b"")
    assert line is None or len(line) <= MAX_LINE_LENGTH


LINES = st.lists(
    st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=1, max_size=200)
    .filter(lambda s: s.strip()),
    min_size=1, max_size=5,
)


@given(LINES, st.integers(1,50))
def test_read_line_reassembles_any_chunking(lines, chunk_size):
    data = ("\n".join(lines) + "\n").encode()
    chunks = [data[i: i + chunk_size] for i in range(0, len(data), chunk_size)]
    sock, buf, got = FakeSock(chunks), b"", []
    for _ in lines:
        line, buf = read_line(sock, buf)
        got.append(line)
    assert got == [s.strip() for s in lines]