from enum import Enum


class Command(str, Enum):
    LOGIN = "LOGIN"
    REGISTER = "REGISTER"
    MSG = "MSG"
    KICK = "KICK"
    BAN = "BAN"
    UNBAN = "UNBAN"
    SET = "SET"
    CLIENT_IP = "CLIENT_IP"

class ErrorCode(str, Enum):
    ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN"
    BANNED = "BANNED"
    WRONG_AUTH = "WRONG_AUTH"
    INVALID_FORMAT = "INVALID_FORMAT"
    INVALID_COMMAND = "INVALID_COMMAND"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    CONNECTION_LIMIT_REACHED = "CONNECTION_LIMIT_REACHED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    MESSAGE_TOO_LONG = "MESSAGE_TOO_LONG"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    INVALID_ROLE = "INVALID_ROLE"

def parse_command(line: str) -> tuple[Command | None, list[str]]:
    if not line or not line.strip():
        return None, []
    parts = line.strip().split()
    try:
        command = Command(parts[0].upper())
    except ValueError:
        return None, []
    return command, parts[1:]

def ok(detail: str = "") -> str:
    return f"OK {detail}\n" if detail else "OK\n"

def error(code: ErrorCode, detail: str = "") -> str:
    return f"ERR {code.value} {detail}\n" if detail else f"ERR {code.value}\n"

def chat_message(text: str) -> str:
    if not text:
        raise ValueError("chat_message() requires non-empty text")
    return f"MSG {text}\n"