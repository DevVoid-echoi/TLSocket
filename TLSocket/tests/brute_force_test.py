import random
import socket
import ssl  # Import the ssl module
import time

from tlsocket.config import CERT_FILE, HOST, PORT

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(str(CERT_FILE))

context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False

def simulate_brute_force(fake_ip: str, attempts: int = 6):
    """
    Simulate a brute-force attack by sending multiple failed login attempts from a fake IP address.
    """
    print(f"\n==========================================")
    print(f"[TEST] Simulate a brute-force attack from ip: {fake_ip}")
    print(f"==========================================")

    for i in range(1, attempts + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))

            # Wrap the socket with SSL
            tls_sock = context.wrap_socket(sock, server_hostname=HOST)

            tls_sock.send(f"CLIENT_IP {fake_ip}\n".encode("utf-8"))
            
            time.sleep(0.05)

            fake_user = f"victim_user"
            fake_pass = f"wrong_password_{i}"
            tls_sock.send(f"LOGIN {fake_user} {fake_pass}\n".encode("utf-8"))

            response = tls_sock.recv(1024).decode("utf-8").strip()
            print(f" -> Lần {i}: Server phản hồi => {response}")

            tls_sock.close()
            time.sleep(0.1)

        except Exception as e:
            print(f" -> Lần {i}: Lỗi kết nối Socket => {e}")
            break

if __name__ == "__main__":
    index = 0
    for index in range(1, 50):
        simulate_brute_force(fake_ip="10.0.0." + str(index), attempts=random.randint(1, 10))
