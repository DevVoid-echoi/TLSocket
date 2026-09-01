import socket
import time
import sys
import os

# Thêm đường dẫn gốc để import config nếu cần
PARENT_DIR = os.path.dirname(os.path.abspath(__file__))
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from config import HOST, PORT

def simulate_brute_force(fake_ip: str, attempts: int = 6):
    """
    Giả lập 1 IP cố định thực hiện Brute-Force đăng nhập sai nhiều lần
    """
    print(f"\n==========================================")
    print(f"[TEST] Đang kiểm tra Brute-Force với Virtual IP: {fake_ip}")
    print(f"==========================================")

    for i in range(1, attempts + 1):
        try:
            # Tạo kết nối Socket mới cho mỗi lần thử
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))

            # 1. Gửi IP giả lập ngay khi kết nối
            sock.send(f"CLIENT_IP {fake_ip}\n".encode("utf-8"))
            
            # Cho Server chút thời gian xử lý gói CLIENT_IP
            time.sleep(0.05)

            # 2. Gửi lệnh LOGIN sai mật khẩu
            fake_user = f"victim_user"
            fake_pass = f"wrong_password_{i}"
            sock.send(f"LOGIN {fake_user} {fake_pass}\n".encode("utf-8"))

            # 3. Nhận phản hồi từ Server
            response = sock.recv(1024).decode("utf-8").strip()
            print(f" -> Lần {i}: Server phản hồi => {response}")

            sock.close()
            time.sleep(0.1)

        except Exception as e:
            print(f" -> Lần {i}: Lỗi kết nối Socket => {e}")
            break

if __name__ == "__main__":
    # Test 1: Giả lập IP 10.0.0.9 đánh sai 6 lần (Lần thứ 6 sẽ bị SERVER BLOCK ngay từ đầu)
    simulate_brute_force(fake_ip="10.0.0.9", attempts=6)

    # Test 2: Giả lập IP 10.0.0.8 (IP khác vẫn hoạt động bình thường, không bị ảnh hưởng)
    simulate_brute_force(fake_ip="10.0.0.8", attempts=2)