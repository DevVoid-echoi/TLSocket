import socket
import ssl
import time

from tlsocket.config import CERT_FILE, HOST, PORT

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(str(CERT_FILE))
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False


def simulate_login_ddos(fake_ip: str):
    print(f"\n==========================================")
    print(f"[TEST] Simulate a login DDoS attack from ip: {fake_ip}")
    print(f"==========================================")

    for i in range(1, 100000000):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            wrapped_socket = context.wrap_socket(sock, server_hostname=HOST)  # Wrap the socket in TLS

            wrapped_socket.send(f"CLIENT_IP {fake_ip}\n".encode("utf-8"))
            
            time.sleep(0.05)
            
            fake_user = i
            fake_pass = f"wrong_password_{i}"
            wrapped_socket.send(f"LOGIN {fake_user} {fake_pass}\n".encode("utf-8"))

            response = wrapped_socket.recv(1024).decode("utf-8").strip()
            print(f" -> Lần {i}: Server phản hồi => {response}")

            wrapped_socket.close()
            time.sleep(0.1)

        except Exception as e:
            print(f" -> Lần {i}: Lỗi kết nối Socket => {e}")
            break

if __name__ == "__main__":
    index = 0
    for index in range(1, 100000000):
        simulate_login_ddos(fake_ip="10.0.0." + str(index))
