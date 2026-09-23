import socket
import ssl
import sys

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    with socket.create_connection(("localhost", 9999), timeout=3) as raw:
        with ctx.wrap_socket(raw) as tls:
            tls.sendall(b"PING\n")
            reply = tls.recv(16)
    sys.exit(0 if reply.strip() == b"PONG" else 1)
except OSError:
    sys.exit(1)