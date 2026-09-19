import time

import pytest

from tlsocket.server_side.handlers import client_handler as ch


def test_register_then_login_succeeds(make_client):
    alice = make_client()
    alice.send("REGISTER alice pw123")
    assert alice.recv_line() == "OK Registration successful"

    alice.send("LOGIN alice pw123")
    assert alice.recv_line() == "OK Connected as alice, role:user"

def test_second_user_join_is_broadcast_and_messages_relay(make_client):
    alice = make_client()
    alice.send("REGISTER alice pw123")
    alice.recv_line()
    alice.send("LOGIN alice pw123")
    assert alice.recv_line() == "OK Connected as alice, role:user"

    bob = make_client()
    bob.send("REGISTER bob pw123")
    bob.recv_line()
    bob.send("LOGIN bob pw123")
    bob.recv_line()

    assert alice.recv_line() == "MSG bob joined the chat!"

    bob.send("MSG hello")
    assert alice.recv_line() == "MSG bob: hello"

def test_plain_user_cannot_kick(make_client):
    alice = make_client()
    alice.send("REGISTER alice pw123")
    alice.recv_line()
    alice.send("LOGIN alice pw123")
    alice.recv_line()

    alice.send("KICK ghost")
    assert alice.recv_line() == "MSG PERMISSION_DENIED: You do not have KICK permission."

def test_moderator_can_kick_user(make_client):
    from tlsocket.auth import authentication as auth

    alice = make_client()
    alice.send("REGISTER alice pw123")
    alice.recv_line()
    auth.set_user_role("alice", "moderator")
    alice.send("LOGIN alice pw123")
    assert alice.recv_line() == "OK Connected as alice, role:moderator"

    bob = make_client()
    bob.send("REGISTER bob pw123")
    bob.recv_line()
    bob.send("LOGIN bob pw123")
    bob.recv_line()
    assert alice.recv_line() == "MSG bob joined the chat!"

    alice.send("KICK bob")
    assert bob.recv_line() == "MSG You were kicked!"
    received = {alice.recv_line(), alice.recv_line()}
    assert received == {"MSG bob left the chat!", "MSG bob was kicked by alice!"}

def test_login_while_already_online_is_rejected(make_client):
    alice1 = make_client()
    alice1.send("REGISTER alice pw123")
    alice1.recv_line()
    alice1.send("LOGIN alice pw123")
    assert alice1.recv_line() == "OK Connected as alice, role:user"

    alice2 = make_client()
    alice2.send("LOGIN alice pw123")
    assert alice2.recv_line() == "ERR ALREADY_LOGGED_IN"

def test_disconnect_cleans_up_server_state(make_client):
    alice = make_client()
    alice.send("REGISTER alice pw123")
    alice.recv_line()
    alice.send("LOGIN alice pw123")
    alice.recv_line()
    assert ch.registry.by_name("alice") is not None

    alice.close()

    deadline = time.time() + 2
    while ch.registry.by_name("alice") is not None and time.time() < deadline:
        time.sleep(0.05)

    assert ch.registry.by_name("alice") is None
    assert ch.registry._ip_counts == {}

def test_register_rate_limiter_per_ip(make_client):
    from tlsocket.config import MAX_REGISTER_ATTEMPTS

    client = make_client()
    for i in range(MAX_REGISTER_ATTEMPTS):
        client.send(f"REGISTER user{i} pw123")
        assert client.recv_line() == "OK Registration successful"

    blocked_client = make_client()
    blocked_client.send("REGISTER blocked_user pw123")
    assert blocked_client.recv_line().startswith("ERR RATE_LIMIT_EXCEEDED")

def test_message_flood_is_rate_limited(make_client):
    from tlsocket.config import MAX_MESSAGES_PER_WINDOW

    client = make_client()
    client.send("REGISTER alice pw123")
    client.recv_line()
    client.send("LOGIN alice pw123")
    client.recv_line()

    for i in range(MAX_MESSAGES_PER_WINDOW):
        client.send(f"MSG hello {i}")

    client.send("MSG one_too_many")
    assert client.recv_line().startswith("ERR RATE_LIMIT_EXCEEDED")

def test_connect_with_backoff_raises_after_exhausting_retries(running_server, make_client):
    from tlsocket.client_side.client_management.connection import (
        ServerRejectedError,
        connect_with_backoff,
    )
    from tlsocket.config import CERT_FILE, MAX_CONNECTIONS_PER_IP

    port = running_server
    _blockers = [make_client() for _ in range(MAX_CONNECTIONS_PER_IP)]

    with pytest.raises(ServerRejectedError):
        connect_with_backoff("localhost", port, CERT_FILE, max_retries=2, base_delay=0.05)