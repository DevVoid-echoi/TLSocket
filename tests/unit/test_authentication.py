import json

import pytest

from tlsocket.auth import authentication as auth


@pytest.fixture
def isolated_auth_files(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "USERS_FILE", tmp_path / "user.json")
    monkeypatch.setattr(auth, "BAN_FILE", tmp_path / "ban.txt")


pytestmark = pytest.mark.usefixtures("isolated_auth_files")

def test_register_success():
    ok, msg = auth.register("alice", "pw123")
    assert ok is True
    assert msg == "Registration successful"
    assert auth.USERS_FILE.exists()

def test_register_stores_hashed_password_not_plaintext():
    auth.register("alice", "pw123")
    users = json.loads(auth.USERS_FILE.read_text())
    assert users["alice"]["password_hash"] != "pw123"
    assert users["alice"]["role"] == "user"

def test_register_duplicate_case_insensitive():
    auth.register("alice", "pw123")
    ok, msg = auth.register("Alice", "other_pw")
    assert ok is False
    assert msg == "User already exists"

def test_register_invalid_nickname():
    ok, msg = auth.register("a b", "pw123")
    assert ok is False
    assert msg == "Invalid username"

def test_register_custom_role():
    auth.register("bob", "pw123", role="moderator")
    users = json.loads(auth.USERS_FILE.read_text())
    assert users["bob"]["role"] == "moderator"

def test_login_success_returns_session():
    auth.register("alice", "pw123")
    ok, session = auth.login("alice", "pw123")
    assert ok is True
    assert session["username"] == "alice"
    assert session["role"] == "user"
    assert session["authentication"] is True

def test_login_wrong_password():
    auth.register("alice", "pw123")
    ok, session = auth.login("alice", "wrong")
    assert(ok,session) == (False, None)

def test_login_user_not_found():
    ok, session = auth.login("unknown", "pw123")
    assert(ok, session) == (False, None)

def test_login_banned_user_returns_true_but_no_session():
    """Contract lạ nhưng có chủ đích: mật khẩu đúng + bị ban -> (True, None).
    server.py dựa vào việc success=True để phân biệt với sai mật khẩu,
    rồi tự kiểm tra `user_session is None` để biết là bị ban."""
    auth.register("alice", "pw123")
    auth.BAN_FILE.write_text("alice\n")
    ok, session = auth.login("alice", "pw123")
    assert(ok, session) == (True, None)

def test_set_user_role_sucess():
    auth.register("alice", "pw123")
    assert auth.set_user_role("alice", "moderator") is True
    users = json.loads(auth.USERS_FILE.read_text())
    assert users["alice"]["role"] == "moderator"

def test_set_user_role_invalid_role():
    auth.register("alice", "pw123")
    assert auth.set_user_role("alice", "advisor") is False

def test_set_user_role_user_not_found():
    assert auth.set_user_role("unknown", "admin") is False

def test_verify_password_matches_correct_password():
    auth.register("alice", "pw123")
    users = json.loads(auth.USERS_FILE.read_text())
    stored_harsh = users["alice"]["password_hash"]
    assert auth.verify_password(stored_harsh, "pw123") is True
    assert auth.verify_password(stored_harsh, "wrong") is False

def test_same_password_hash_different():
    auth.register("alice", "pw123")
    auth.register("bob", "pw123")
    users = json.loads(auth.USERS_FILE.read_text())
    alice_hash = users["alice"]["password_hash"]
    bob_hash = users["bob"]["password_hash"]
    assert alice_hash != bob_hash
    assert alice_hash.startswith("$argon2id$")
    assert bob_hash.startswith("$argon2id$")

def test_needs_rehash_true_for_legacy_hash():
    legacy = auth._legacy_hash_password("pw123")
    assert auth.needs_rehash(legacy) is True

def test_needs_rehash_false_for_fresh_argon2_hash():
    fresh = auth._hash_password("pw123")
    assert auth.needs_rehash(fresh) is False

def test_verify_password_still_validates_legacy_hash():
    legacy_hash = auth._legacy_hash_password("pw123")
    assert auth.verify_password(legacy_hash, "pw123") is True
    assert auth.verify_password(legacy_hash, "wrong") is False

def test_test_migrates_legacy_hash_to_argon2():
    legacy_hash = auth._legacy_hash_password("pw123")
    auth.USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    auth.USERS_FILE.write_text(json.dumps({
        "alice": {"password_hash": legacy_hash, "role": "user"}
    }))

    ok, session = auth.login("alice", "pw123")
    assert ok is True
    assert session is not None

    users = json.loads(auth.USERS_FILE.read_text())
    assert users["alice"]["password_hash"].startswith("$argon2id$")

    ok2, session2 = auth.login("alice", "pw123")
    assert ok2 is True
    assert session2 is not None

def test_load_users_with_corrupted_json_returns_empty():
    auth.USERS_FILE.write_text("{ not valid json")
    ok, session = auth.login("alice", "pw123")
    assert(ok, session) == (False, None)

def test_banned_users_file_unreadable_defaults_to_no_bans():
    auth.register("alice", "pw123")
    auth.BAN_FILE.mkdir()
    ok, session = auth.login("alice", "pw123")
    assert ok is True
    assert session is not None