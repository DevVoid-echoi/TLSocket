import time

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tlsocket.server_side.handlers import client_handler as ch

CHUNKS = st.one_of(
    st.binary(max_size=60),
    st.sampled_from([b"LOGIN ", b"REGISTER ", b"MSG ", b"KICK ", b"PING\n", b"\n", b"\x00", b"A" * 5000]),
)

def _wait_drained(timeout=3.0):
    end = time.time() + timeout
    while ch.registry._ip_counts and time.time() < end:
        time.sleep(0.05)

@settings(max_examples=25, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(CHUNKS, max_size=12).map(b"".join))
def test_survives_arbitrary_bytes(make_client, payload):
    _wait_drained()
    c = make_client()
    try:
        c.sock.sendall(payload)
    except OSError:
        pass
    c.close()
    _wait_drained()
    probe = make_client()
    probe.send("PING")
    assert probe.recv_line() == "PONG"
    probe.close()
    _wait_drained()
    assert ch.registry._ip_counts == {}