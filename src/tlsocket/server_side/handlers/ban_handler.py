from tlsocket.config import BAN_FILE as BAN_FILE_PATH


def get_banned_users():
    """Read the ban file for banned users"""
    if not BAN_FILE_PATH.exists():
        return []
    with open(BAN_FILE_PATH, 'r', encoding="utf-8") as f:
        return [line.strip().lower() for line in f.readlines() if line.strip()]

def add_ban(nickname):
    """Add ban users"""
    nickname = nickname.strip().lower()
    if not nickname or nickname in get_banned_users():
        return
    BAN_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BAN_FILE_PATH, 'a', encoding="utf-8") as f:
        f.write(f"{nickname}\n")

def remove_ban(nickname):
    """Remove banned users"""
    nickname = nickname.strip().lower()
    banned_users = get_banned_users()
    if nickname in banned_users:
        banned_users.remove(nickname)
        with open(BAN_FILE_PATH, 'w', encoding="utf-8") as f:
            for user in banned_users:
                f.write(f"{user}\n")
