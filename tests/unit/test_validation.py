import pytest

from tlsocket.security.validation import (
    parse_and_validate_command,
    validate_message,
    validate_nickname,
)


def test_valid_nickname_ok():
    valid, msg = validate_nickname("alice")
    assert valid is True
    assert msg == "OK"

def test_nickname_too_short_or_empty():
    valid, msg = validate_nickname("")
    assert valid is False
    assert msg.startswith("EMPTY_NICKNAME")

def test_nickname_none_is_invalid():
    valid, _ = validate_nickname(None)
    assert valid is False

def test_nickname_rejects_control_chars():
    for b in ["ab\ncd", "ab\rcd", "ab\x00cd"]:
        valid, msg = validate_nickname(b)
        assert valid is False
        assert msg.startswith("INVALID_CHARACTERS")

def test_nickname_too_long():
    valid, msg = validate_nickname("a" * 21)
    assert valid is False
    assert msg.startswith("INVALID_LENGTH")

def test_nickname_rejects_special_chars():
    valid, msg = validate_nickname("a!")
    assert valid is False
    assert msg.startswith("INVALID_CHARACTERS")

def test_nickname_admin_is_rejected():
    valid, msg = validate_nickname("admin")
    assert valid is False
    assert msg.startswith("FORBIDDEN_NICKNAME")

@pytest.mark.parametrize("message", ["", "   ", None])
def test_message_empty_variants_rejected(message):
    valid, msg = validate_message(message)
    assert valid is False
    assert "EMPTY_MESSAGE" in msg

def test_message_null_byte_rejected():
    valid, msg = validate_message("hi\x00there")
    assert valid is False
    assert msg.startswith("INVALID_CHARACTERS")

def test_message_at_max_length_ok():
    valid, _ = validate_message("a" * 1000)  # MAX_MESSAGE_LENGTH
    assert valid is True

def test_message_over_max_length_rejected():
    valid, msg = validate_message("a" * 1001)
    assert valid is False
    assert msg.startswith("MESSAGE_TOO_LONG")

def test_valid_message_ok():
    valid, msg = validate_message("hello world")
    assert valid is True
    assert msg == "OK"

def test_parse_kick_command_ok():
    cmd, args, err = parse_and_validate_command("KICK alice")
    assert(cmd, args, err) == ("KICK", ["alice"], "OK")

def test_parse_command_is_uppercased():
    cmd, _, _ = parse_and_validate_command("kick alice")
    assert cmd == "KICK"

@pytest.mark.parametrize("cmd_name", ["KICK", "BAN", "UNBAN"])
def test_kick_ban_unban_require_exactly_one_arg(cmd_name):
    _, _, err = parse_and_validate_command(cmd_name)
    assert err.startswith("SYNTAX_USAGE")
    _, _, err = parse_and_validate_command(f"{cmd_name} a b")
    assert err.startswith("TOO_MANY_ARGUMENTS")

def test_set_requires_exactly_two_args():
    _, _, err = parse_and_validate_command("SET alice")
    assert err.startswith("SYNTAX_USAGE")
    _, _, err = parse_and_validate_command("SET alice admin user")
    assert err.startswith("SYNTAX_USAGE")
    cmd, args, err = parse_and_validate_command("SET alice admin")
    assert(cmd, args, err) == ("SET", ["alice", "admin"], "OK")

@pytest.mark.parametrize("line", ["", " "])
def test_empty_command_line(line):
    cmd, args, err = parse_and_validate_command(line)
    assert(cmd, args) == ("", [])
    assert err.startswith("EMPTY_COMMAND")
                            
