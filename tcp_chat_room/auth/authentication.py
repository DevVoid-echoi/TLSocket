import os
import json
import hashlib
import sys

"""Path to base directory(To import config)"""
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(BASE_DIR, "data", "user.json")
BAN_FILE = os.path.join(BASE_DIR, "data", "ban.txt")
SECURITY_DIR = os.path.join(BASE_DIR, "security")

from auth.password import ADMIN_PASSWORD
from security.validation import validate_nickname

def _load_users():
    """Read accounts from JSON file"""
    if not os.path.exists(USERS_FILE):
        return{}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _load_banned_users() -> set:
    if not os.path.exists(BAN_FILE):
        return set()
    try:
        with open(BAN_FILE, "r", encoding='utf-8') as f:
            return {line.strip().lower() for line in f if line.strip()}
    except Exception:
        return set()

def _save_users(users):
    """Save accounts into JSON file"""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)

def _hash_password(password:str)->str:
    """Hash password with SHA-256 and salt"""
    salt = "tcp_chat_room_salt_2026"
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()

def verify_password(stored_hash:str, provided_password: str)->bool:
    """Compare provided password with hash password"""
    return stored_hash == _hash_password(provided_password)

def register(username, password, role="user"):
    """Register new account"""
    username = username.strip().lower()
    valid, err_nickname = validate_nickname(username)
    if not valid:
        return False, "Invalid username"

    users = _load_users()

    if username in users:
        print(f"[AUTH LOG] Register failed: User '{username}' already exists.")
        return False, "User already exists"

    users[username] = {
        "password_hash": _hash_password(password),
        "role": role
    }

    _save_users(users)
    print(f"[AUTH LOG] Register success: User '{username}' registered with role '{role}'.")
    return True, "Registration successful"

def login(username, password):
    """Login and start an information session"""
    username = username.strip().lower()
    users = _load_users()

    # Register an admin acoount if the acoount list is blank
    if not users and username == "admin":
        register("admin", ADMIN_PASSWORD, role="admin")
        users = _load_users()

    if username not in users:
        print(f"[AUTH LOG] Login failed: Username '{username}' not found.")
        return False, None

    user_data = users[username]
    if verify_password(user_data["password_hash"], password):
        banned_users = _load_banned_users()
        if username in banned_users:
            print(f"[AUTH LOG] Login failed: User '{username}' is banned.")
            return True, None

        # Create a session object to return when the authentication succeed
        else:
            session = {
                "username": username,
                "role": user_data.get("role", "user"),
                "authentication": True
            }

            print(f"[AUTH LOG] Login success: User '{username}' logged in successfully.")
            return True, session
    else:
        print(f"[AUTH LOG] Login failed: Invalid password for user '{username}'.")
        return False, None

def set_user_role(username: str, new_role: str) -> bool:
    """Assign new role for an acoount"""
    username = username.strip().lower()
    new_role = new_role.strip().lower()

    if new_role not in ["admin", "user"]:
        print(f"[AUTH LOG] Set role failed: Invalid role '{new_role}'.")
        return False

    users = _load_users()
    if username not in users:
        print(f"[AUTH LOG] Set role failed: User '{username}' not found.")
        return False

    users[username]["role"] = new_role
    _save_users(users)
    print(f"[AUTH LOG] Success: User '{username}' assigned role '{new_role}'.")
    return True