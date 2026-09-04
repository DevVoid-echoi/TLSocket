import socket
import time
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from config import HOST, PORT

def simulate_login_ddos(fake_ip: str):
    print(f"\n==========================================")
    print(f"[TEST] Simulate a login DDoS attack from ip: {fake_ip}")
    print(f"==========================================")

    for i in range(1, 100000000):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))

            sock.send(f"CLIENT_IP {fake_ip}\n".encode("utf-8"))
            
            time.sleep(0.05)
            
            fake_user = i
            fake_pass = f"wrong_password_{i}"
            sock.send(f"LOGIN {fake_user} {fake_pass}\n".encode("utf-8"))

            response = sock.recv(1024).decode("utf-8").strip()
            print(f" -> Lần {i}: Server phản hồi => {response}")

            sock.close()
            time.sleep(0.1)

        except Exception as e:
            print(f" -> Lần {i}: Lỗi kết nối Socket => {e}")
            break

if __name__ == "__main__":
    index = 0
    for index in range (1, 100000000):
        simulate_login_ddos(fake_ip="10.0.0." + str(index))