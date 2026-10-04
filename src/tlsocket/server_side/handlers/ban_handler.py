import os
import threading

from tlsocket.config import BAN_FILE as BAN_FILE_PATH

_ban_lock = threading.Lock()


def get_banned_users() -> list[str]:
    """Read the ban file for banned users"""
    if not BAN_FILE_PATH.exists():
        return []
    with open(BAN_FILE_PATH, encoding="utf-8") as f:
        return [line.strip().lower() for line in f.readlines() if line.strip()]

def _save_banned_users(users: list[str]) -> None:
    BAN_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = BAN_FILE_PATH.parent / (BAN_FILE_PATH.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        for user in users:
            f.write(f"{user}\n")
    os.replace(tmp_path, BAN_FILE_PATH)

def add_ban(nickname: str) -> None:
    """Add ban users"""
    nickname = nickname.strip().lower()
    if not nickname:
        return
    with _ban_lock:
        users = get_banned_users()
        if nickname in users:
            return
        users.append(nickname)
        _save_banned_users(users)

def remove_ban(nickname: str) -> None:
    """Remove banned users"""
    nickname = nickname.strip().lower()
    with _ban_lock:
        banned_users = get_banned_users()
        if nickname in banned_users:
            banned_users.remove(nickname)
            _save_banned_users(banned_users)
