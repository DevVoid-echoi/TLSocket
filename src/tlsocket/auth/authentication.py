import hashlib
import hmac
import json
import os
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from tlsocket.config import BAN_FILE, USERS_FILE
from tlsocket.security.validation import validate_nickname

_ph = PasswordHasher()

_LEGACY_SALT = "tcp_chat_room_salt_2026"

def _load_users() -> dict[str, Any]:
    """Read accounts from JSON file"""
    if not os.path.exists(USERS_FILE):
        return{}
    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
            return data
    except Exception:
        return {}

def _load_banned_users() -> set[str]:
    if not os.path.exists(BAN_FILE):
        return set()
    try:
        with open(BAN_FILE, encoding='utf-8') as f:
            return {line.strip().lower() for line in f if line.strip()}
    except Exception:
        return set()

def _save_users(users: dict[str, Any]) -> None:
    """Save accounts into JSON file"""
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)

def _legacy_hash_password(password: str) -> str:
    """SHA-256 + salt tĩnh dùng chung cho mọi user - thuật toán CŨ, không an
    toàn. Chỉ dùng để verify hash cũ, không dùng để tạo hash mới."""
    return hashlib.sha256((password + _LEGACY_SALT).encode("utf-8")).hexdigest()

def _hash_password(password: str) -> str:
    """Hash mật khẩu bằng Argon2id - salt ngẫu nhiên tự sinh, tự nhúng vào
    chuỗi kết quả, không cần lưu salt riêng."""
    return _ph.hash(password)

def _is_legacy_hash(stored_hash: str) -> bool:
    return not stored_hash.startswith("$argon2")

def needs_rehash(stored_hash: str) -> bool:
    """True nếu hash cần tính lại theo thuật toán/tham số hiện tại:
    - hash cũ (SHA-256): luôn cần.
    - hash Argon2id: chỉ cần khi tham số cost đã đổi so với lúc hash (vd sau
      này nâng cấp độ khó của _ph)."""
    if _is_legacy_hash(stored_hash):
        return True
    return _ph.check_needs_rehash(stored_hash)

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """So khớp mật khẩu, hỗ trợ cả hash Argon2id (mới) lẫn SHA-256+salt tĩnh
    (cũ, để còn đăng nhập được trước khi needs_rehash() migrate nó)."""
    if _is_legacy_hash(stored_hash):
        return hmac.compare_digest(stored_hash, _legacy_hash_password(provided_password))
    try:
        return bool(_ph.verify(stored_hash, provided_password))
    except (VerifyMismatchError, InvalidHashError):
        return False

def register(username: str, password: str, role: str = "user") -> tuple[bool, str]:
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

def login(username: str, password: str) -> tuple[bool, dict[str, Any] | None]:
    """Login and start an information session"""
    username = username.strip().lower()
    users = _load_users()

    if username not in users:
        print(f"[AUTH LOG] Login failed: Username '{username}' not found.")
        return False, None

    user_data = users[username]
    if verify_password(user_data["password_hash"], password):
        if needs_rehash(user_data["password_hash"]):
            user_data["password_hash"] = _hash_password(password)
            users[username] = user_data
            _save_users(users)
            print(f"[AUTH LOG] Rehashed password for user '{username}' to Argon2id.")
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

    if new_role not in ["admin","moderator", "user"]:
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