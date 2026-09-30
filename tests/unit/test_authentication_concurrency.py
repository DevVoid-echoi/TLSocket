from concurrent.futures import ThreadPoolExecutor

from tlsocket.auth import authentication as auth


def test_concurrent_registrations_do_not_lose_accounts(monkeypatch, tmp_path):
    monkeypatch.setattr(auth, "USERS_FILE", tmp_path / "user.json")

    for i in range(50):
        auth.register(f"seed{i}", "pw123")

    def do_register(i):
        return auth.register(f"new{i}", "pw123")

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(do_register, range(30)))

    assert all(ok for ok, _ in results)
    users = auth._load_users()
    assert len(users) == 50 +30