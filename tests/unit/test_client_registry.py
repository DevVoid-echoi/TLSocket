import threading
import time

from tlsocket.server_side.client_registry import ClientRegistry, Session


class _FakeSocket:
    def __init__(self, fail=False):
        self.fail = fail
        self.send=[]
        self._timeout = None

    def gettimeout(self):
        return self._timeout

    def settimeout(self, value):
        self._timeout = value

    def sendall(self, data):
        if self.fail:
            raise BrokenPipeError()
        self.send.append(data)

    def shutdown(self, how):
        pass

    def close(self):
        pass

class _SlowSocket:
    def __init__(self):
        self.release = threading.Event()
        self._shutdown = False

    def sendall(self, data):
        self.release.wait(timeout=5)
        if self._shutdown:
            raise OSError("Socket is not connected") 

    def gettimeout(self):
        return None

    def settimeout(self, value):
        pass

    def shutdown(self, how):
        self._shutdown = True
        self.release.set()

    def close(self):
        pass

def _wait_until(predicate, timeout=1.0):
    deadline = time.time() + timeout
    while not predicate() and time.time() < deadline:
        time.sleep(0.01)
    return predicate()

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

def test_release_ip_slot_ignores_unknown_socket():
    registry = ClientRegistry(max_connections_per_ip=1)
    registry.try_reserve_ip_slot("sock1", "1.1.1.1")
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is False
    registry.release_ip_slot("unknow_sock")
    assert registry.try_reserve_ip_slot("sock2", "1.1.1.1") is False 

def test_add_and_session():
    registry = ClientRegistry(max_connections_per_ip=5)
    session = Session(username="alice", role="user")
    sock = _FakeSocket()
    registry.add(sock, session)
    assert registry.get_session(sock) is session
    assert registry.by_name("alice") == sock

def test_remove_returns_session_and_clears_by_name():
    registry = ClientRegistry(max_connections_per_ip=5)
    session = Session(username="alice", role="user")
    sock = _FakeSocket()
    registry.add(sock, session)
    removed = registry.remove(sock)
    assert removed is session
    assert registry.get_session(sock) is None
    assert registry.by_name("alice") is None

def test_remove_socket_returns_none():
    registry = ClientRegistry(max_connections_per_ip=5)
    assert registry.remove("unknown") is None

def test_remove_does_not_clobber_reused_username():
    registry = ClientRegistry(max_connections_per_ip=5)
    sock_old, sock_new = _FakeSocket(), _FakeSocket()
    registry.add(sock_old, Session(username="alice", role="user"))
    registry.add(sock_new, Session(username="alice", role="user"))
    registry.remove(sock_old)
    assert registry.by_name("alice") == sock_new

def test_snapshot_returns_current_socket():
    registry = ClientRegistry(max_connections_per_ip=5)
    sock1, sock2 = _FakeSocket(), _FakeSocket()
    registry.add(sock1, Session(username="alice", role="user"))
    registry.add(sock2, Session(username="bob", role="user"))
    assert set(registry.snapshot()) == {sock1, sock2}

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
    sock = _FakeSocket()
    registry.add(sock, Session(username="alice", role="user"))
    assert registry.reserve_username("alice") is False

def test_add_clears_pending_reservation():
    registry = ClientRegistry(max_connections_per_ip=5)
    registry.reserve_username("alice")
    sock = _FakeSocket()
    registry.add(sock, Session(username="alice", role="user"))
    registry.remove(sock)
    assert registry.reserve_username("alice") is True

def test_set_role_updates_session_and_returns_socket():
    registry = ClientRegistry(max_connections_per_ip=5)
    sock = _FakeSocket()
    registry.add(sock, Session(username="alice", role="user"))
    result = registry.set_role("alice", "moderator")
    assert result == sock
    assert registry.get_session(sock).role == "moderator"

def test_set_role_returns_none_for_offline_user():
    registry = ClientRegistry(max_connections_per_ip=5)
    assert registry.set_role("unknown", "moderator") is None

def test_send_success_returns_true_and_delievers():
    registry = ClientRegistry(max_connections_per_ip=5)
    sock = _FakeSocket()
    registry.add(sock, Session(username="x", role="user"))
    assert registry.send(sock, b"Hello") is True
    assert _wait_until(lambda: sock.send == [b"Hello"])

def test_send_to_unregistered_socket_returns_false():
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
    assert _wait_until(lambda: bob.send == [b"hi"])

def test_broadcast_reports_failed_sockets_when_queue_is_full():
    from tlsocket.config import SEND_QUEUE_MAXSIZE

    registry = ClientRegistry(max_connections_per_ip=5)
    good, overloaded = _FakeSocket(), _SlowSocket()
    registry.add(good, Session(username="good", role="user"))
    registry.add(overloaded, Session(username="overloaded", role="user"))

    for _ in range(SEND_QUEUE_MAXSIZE + 1):
        registry.send(overloaded, b"filler")

    failed = registry.broadcast(b"hi")
    assert failed == [overloaded]
    assert registry.get_session(overloaded) is not None

    overloaded.release.set()

def test_slow_socket_client_does_not_block_sends_to_other_clients():
    registry = ClientRegistry(max_connections_per_ip=5)
    slow = _SlowSocket()
    fast = _FakeSocket()
    registry.add(slow, Session(username="slow", role="user"))
    registry.add(fast, Session(username="fast", role="user"))

    t = threading.Thread(target=registry.send, args=(slow, b"to_slow"))
    t.start()
    time.sleep(0.2)

    t0 = time.perf_counter()
    ok = registry.send(fast, b"to-fast")
    elapsed = time.perf_counter() - t0

    slow.release.set()
    t.join()

    assert ok is True
    assert _wait_until(lambda: fast.send == [b"to-fast"])
    assert elapsed < 1.0, f"send() to fast socket took too long: {elapsed:.2f}s"

def test_stop_wakes_up_a_writer_stuck_in_sendall():
    from tlsocket.config import SEND_QUEUE_MAXSIZE

    registry = ClientRegistry(max_connections_per_ip=5)
    slow = _SlowSocket()
    registry.add(slow, Session(username="victim", role="user"))

    registry.send(slow, b"first")
    writer = registry._writers[slow]
    assert _wait_until(lambda: writer.queue.qsize() == 0) 

    for _ in range(SEND_QUEUE_MAXSIZE):
        registry.send(slow, b"filler")  

    registry.remove(slow)

    assert _wait_until(lambda: not writer.thread.is_alive(), timeout=1.0)
