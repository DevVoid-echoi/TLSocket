import threading
import socket
import sys
import os
import ssl

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
from config import HOST,PORT
from client_management.instructions import print_instructions
from client_management.connection import receive, write, read_line

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(os.path.join(PARENT_DIR, "certs", "server.crt"))

context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = False

#TODO: Allow reconect after connect limit reached

"""
def connect_to_server():
    """Connect using IPv4 and TCP then wrap the socket with SSL context"""
    raw_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client = context.wrap_socket(raw_client, server_hostname=HOST)
        client.connect((HOST, PORT))
    except (ssl.SSLError, OSError) as e:
        print(f"Connection error: {e}")
        sys.exit(1)
"""

def main():
    """Connect using IPv4 and TCP then wrap the socket with SSL context"""
    raw_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client = context.wrap_socket(raw_client, server_hostname=HOST)
        client.connect((HOST, PORT))
    except (ssl.SSLError, OSError) as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    buffer = ""

    """Print Register/Login options"""
    print("=== CHAT SYSTEM AUTHENTICATION ===")
    while True:
        choice = input("Choose (1: Login, 2: Register): ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        """Send LOGIN request and check received message to see if user successfully loginned"""
        if choice == "1":
            try:
                client.send(f"LOGIN {username} {password}\n".encode("utf-8"))
                line, buffer = read_line(client, buffer)
                if line is None: # Close connection if not receive any message
                    print(">> Server closed connection during registration.")
                    client.close()
                    sys.exit(1)

                if line and line.startswith("OK"): # If succcessfully login, print the announcement and set nickname = username
                    print(">> Login successfully!")
                    nickname = username
                    user_role = "user"
                    if "role:" in line:
                        user_role = line.split("role:")[1].strip()
                    print_instructions(nickname, user_role) # Print instructions based on the role of user
                    break

                else: # Show any login error
                    print(f">> Login error: {line}")
            except Exception as e:
                print(f"Error during login: {e}")
                client.close()
                sys.exit(1)


        """Send REGISTER request and check received message to see if user successfully registered"""
        if choice == "2":
            try:
                client.send(f"REGISTER {username} {password}\n".encode("utf-8"))
                line, buffer = read_line(client, buffer)
                if line is None:# Close connection if not receive any message
                    print(">> Server closed connection during registration.")
                    client.close()
                    sys.exit(1)

                print(f">> Phản hồi đăng ký: {line}")# Print the register announcement
            except Exception as e:
                print("Error during registration.")
                client.close()
                sys.exit(1)

    """Close connection if not receive any message or received an error message"""
    if not line or line.startswith("ERR "):
        msg = line[4:]
        print(f"Connection refused: {msg}")
        client.close()
        sys.exit(1)

    """Create receive thread and start thread"""
    receive_thread = threading.Thread(
        target=receive, 
        args=(client, nickname),
        daemon=True
    )
    receive_thread.start()

    """Call write method from connection"""
    write(client, nickname)

    sys.stdout.write("\r\033[K")
    sys.stdout.flush()
    sys.exit(0)

if __name__ == "__main__":
    main()
