import pytest

from tlsocket.protocol import Command, ErrorCode, chat_message, error, ok, parse_command


def test_parse_command_recognizes_known_command():
    cmd, args = parse_command("LOGIN alice pw123")
    assert cmd == Command.LOGIN
    assert args == ["alice", "pw123"]

def test_parse_command_case_insensitive():
    cmd, _ = parse_command("login alice pw123")
    assert cmd == Command.LOGIN

def test_parse_command_unknown_returns_none():
    cmd, args = parse_command("DO alice")
    assert cmd is None
    assert args == []

@pytest.mark.parametrize("line", ["", " "])
def test_parse_command_empty_line_returns_none(line):
    cmd, args = parse_command(line)
    assert cmd is None
    assert args == []

def test_ok_without_detail():
    assert ok() == "OK\n"

def test_ok_with_detail():
    assert ok("Registration successful") == "OK Registration successful\n"

def test_error_without_detail():
    assert error(ErrorCode.ALREADY_LOGGED_IN) == "ERR ALREADY_LOGGED_IN\n"

def test_error_with_detail():
    assert error(ErrorCode.RATE_LIMIT_REACHED, "Try again in 10s") == "ERR RATE_LIMIT_REACHED Try again in 10s\n"

def test_chat_message():
    assert chat_message("alice: hello") == "MSG alice: hello\n"

def test_command_compares_equal_to_plain_string():
    assert Command.LOGIN == "LOGIN"