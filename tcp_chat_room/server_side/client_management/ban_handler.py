import os
import sys

GRANDPARENT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if GRANDPARENT_DIR not in sys.path:
    sys.path.append(GRANDPARENT_DIR)

from config import BAN_FILE_PATH

def get_banned_users():
    """Read the ban file for banned users"""
    if not os.path.exists(BAN_FILE_PATH):
        return []
    with open(BAN_FILE_PATH, 'r', encoding="utf-8") as f:
        return [line.strip() for line in f.readlines()]

def add_ban(nickname):
    """Add ban users"""
    with open(BAN_FILE_PATH, 'a', encoding="utf-8") as f:
        f.write(f"{nickname}\n")

def remove_ban(nickname):
    """Remove banned users"""
    banned_users = get_banned_users()
    if nickname in banned_users:
        banned_users.remove(nickname)
        with open(BAN_FILE_PATH, 'w', encoding="utf-8") as f:
            for user in banned_users:
                f.write(f"{user}\n")
