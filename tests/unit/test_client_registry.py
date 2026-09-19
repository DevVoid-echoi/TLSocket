from tlsocket.server_side.client_registry import ClientRegistry, Session


def test_reserve_ip_slot_up_to_limit():
    registry = ClientRegistry(max_connections_per_ip=2)
    assert registry.try_reserve_ip_slot("sock1", "1.1.1.1") is True
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is True
    assert registry.try_reserve_ip_slot("sock3", "1.1.1.1") is False

def test_reserve_ip_slot_independent_per_ip():
    registry = ClientRegistry(max_connections_per_ip=1)
    assert registry.try_reserve_ip_slot("sock1", "1.1.1.1") is True
    assert registry.try_reserve_ip_slot("sock2", "2.2.2.2") is True

def test_release_ip_slot_frees_up_room():
    registry = ClientRegistry(max_connections_per_ip=1)
    registry.try_reserve_ip_slot("sock1", "1.1.1.1")
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is False
    registry.release_ip_slot("sock1")
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is True 

def test_release_ip_slot_uses_fallback_when_socket_unknown():
    registry = ClientRegistry(max_connections_per_ip=1)
    registry.try_reserve_ip_slot("sock1", "1.1.1.1")
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is False
    registry.release_ip_slot("unknow_sock", fallback_ip="1.1.1.1")
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is True 

def test_add_and_session():
    registry = ClientRegistry(max_connections_per_ip=5)
    session = Session(username="alice", role="user")
    registry.add("sock1", session)
    assert registry.get_session("sock1") is session
    assert registry.by_name("alice") == "sock1"

def test_remove_returns_session_and_clears_by_name():
    registry = ClientRegistry(max_connections_per_ip=5)
    session = Session(username="alice", role="user")
    registry.add("sock1", session)
    removed = registry.remove("sock1")
    assert removed is session
    assert registry.get_session("sock1") is None
    assert registry.by_name("alice") is None

def test_remove_socket_returns_none():
    registry = ClientRegistry(max_connections_per_ip=5)
    assert registry.remove("unknown") is None

def test_remove_does_not_clobber_reused_username():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.add("sock_old", Session(username="alice", role="user"))
    registry.add("sock_new", Session(username="alice", role="user"))
    registry.remove("sock_old")
    assert registry.by_name("alice") == "sock_new"

def test_snapshot_returns_current_socket():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.add("sock1", Session(username="alice", role="user"))
    registry.add("sock2", Session(username="bob", role="user"))
    assert set(registry.snapshot()) == {"sock1", "sock2"}

def test_reserve_username_blocks_duplication():
    registry = ClientRegistry(max_connections_per_ip=5)
    assert registry.reserve_username("alice") is True
    assert registry.reserve_username("alice") is False

def test_release_reservation_frees_it_up():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.reserve_username("alice")
    assert registry.reserve_username("alice") is False
    registry.release_reservation("alice")
    assert registry.reserve_username("alice") is True

def test_reserve_username_blocked_while_already_online():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.add("sock1", Session(username="alice", role="user"))
    assert registry.reserve_username("alice") is False

def test_add_clears_pending_reservation():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.reserve_username("alice")
    registry.add("sock1", Session(username="alice", role="user"))
    registry.remove("sock1")
    assert registry.reserve_username("alice") is True

def test_set_role_updates_session_and_returns_socket():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.add("sock1", Session(username="alice", role="user"))
    result = registry.set_role("alice", "moderator")
    assert result == "sock1"
    assert registry.get_session("sock1").role == "moderator"

def test_set_role_returns_none_for_offline_user():
    registry = ClientRegistry(max_connections_per_ip=5)
    assert registry.set_role("unknown", "moderator") is None

class _FakeSocket:
    def __init__(self, fail=False):
        self.fail = fail
        self.send=[]

    def sendall(self, data):
        if self.fail:
            raise BrokenPipeError()
        self.send.append(data)

def test_send_success_returns_true_and_delievers():
    registry = ClientRegistry(max_connections_per_ip=5)
    sock = _FakeSocket()
    assert registry.send(sock, b"Hello") is True
    assert sock.send == [b"Hello"]

def test_send_failure_returns_false_without_raising():
    registry = ClientRegistry(max_connections_per_ip=5)
    sock = _FakeSocket(fail=True)
    assert registry.send(sock, b"Hello") is False

def test_broadcast_skips_sender():
    registry = ClientRegistry(max_connections_per_ip=5)
    alice, bob = _FakeSocket(), _FakeSocket()
    registry.add(alice, Session(username="alice", role="user"))
    registry.add(bob, Session(username="bob", role="user"))
    failed = registry.broadcast(b"hi", sender=alice)
    assert failed == []
    assert alice.send == []
    assert bob.send == [b"hi"]

def test_broadcast_reports_failed_sockets_without_removing_them():
    registry = ClientRegistry(max_connections_per_ip=5)
    good, bad = _FakeSocket(), _FakeSocket(fail=True)
    registry.add(good, Session(username="good", role="user"))
    registry.add(bad, Session(username="bad", role="user"))
    failed = registry.broadcast(b"hi")
    assert failed == [bad]
    assert registry.get_session(bad) is not None
