import re
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from config import MAX_NICKNAME_LENGTH, MIN_NICKNAME_LENGTH, MAX_MESSAGE_LENGTH

MAX_NICKNAME_LENGTH = MAX_NICKNAME_LENGTH
MIN_NICKNAME_LENGTH = MIN_NICKNAME_LENGTH
MAX_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH

NICKNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]+$')

def validate_nickname(nickname: str) -> tuple[bool, str]:
    if not nickname or not isinstance(nickname, str):
        return False, "EMPTY_NICKNAME Nickname cannot be empty."
    
    if "\x00" in nickname or "\n" in nickname or "\r" in nickname:
        return False, "INVALID_CHARACTERS Nickname cannot contain null or newline characters."
    
    nickname = nickname.strip()

    if len(nickname) < MIN_NICKNAME_LENGTH or len(nickname) > MAX_NICKNAME_LENGTH:
        return False, f"INVALID_LENGTH Nickname must be between {MIN_NICKNAME_LENGTH} and {MAX_NICKNAME_LENGTH} characters."

    if not NICKNAME_REGEX.match(nickname):
        return False, "INVALID_CHARACTERS Nickname can only contain alphanumeric characters and underscores."
    if "admin" in nickname:
        return False, "FORBIDDEN_NICKNAME Nickname cannot contain the word 'admin'."
        
    return True, "OK"

def validate_message(message:str) -> tuple[bool, str]:
    if not message or not isinstance(message, str):
        return False, "EMPTY_MESSAGE Message cannot be empty."
    if "\x00" in message:
        return False, "INVALID_CHARACTERS Message cannot contain null characters."
    
    msg_clean = message.strip()
    if len(msg_clean) == 0:
        return False, "EMPTY_MESSAGE Message cannot be empty or whitespace only."
    if len(msg_clean) > MAX_MESSAGE_LENGTH:
        return False, f"MESSAGE_TOO_LONG Message cannot exceed {MAX_MESSAGE_LENGTH} characters."

    return True, "OK"

def parse_and_validate_command(line:str) -> tuple[str, list[str], str]:
    if not line or not line.strip():
        return "", [], "EMPTY_COMMAND Command cannot be empty."
    
    parts = line.strip().split()
    cmd = parts[0].upper()
    args = parts[1:]

    if cmd in ["KICK", "BAN", "UNBAN"]:
        if len(args) == 0:
            return cmd, [], f"SYNTAX_USAGE {cmd} command requires at least one argument."
        if len(args) > 1:
            return cmd, [], f"TOO_MANY_ARGUMENTS {cmd} command accepts only one argument."
    if cmd in ["SET"]:
        if len(args) != 2:
            return cmd, [], f"SYNTAX_USAGE {cmd} command requires two arguments: <username> <role>."
    
    return cmd, args, "OK"
