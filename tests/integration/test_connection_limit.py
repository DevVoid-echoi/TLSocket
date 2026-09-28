import socket
import time


def _bad_tls_handshake(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"this is not a TLS handshake\r\n")
    try:
        s.recv(100)
    except OSError:
        pass
    s.close()


def test_connection_limit_reached_even_after_failed_tls_handshakes(running_server, make_client):
    port = running_server
    _held = [make_client() for _ in range (5)]
    time.sleep(0.3)

    for _ in range (5):
        _bad_tls_handshake(port)
        time.sleep(0.1)

    extra = make_client()
    extra.sock.settimeout(1.5)
    assert extra.recv_line() == "ERR CONNECTION_LIMIT_REACHED"