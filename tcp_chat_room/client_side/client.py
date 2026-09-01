import threading
import socket
import sys
import os

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from config import HOST,PORT
from client_management.instructions import print_instructions
from client_management.connection import receive, write, read_line

def main():
    """Connect using IPv4 and TCP"""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    buffer = ""

    """Print Register/Login options"""
    print("=== CHAT SYSTEM AUTHENTICATION ===")
    while True:
        choice = input("Choose (1: Login, 2: Register): ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        """Send LOGIN request and check received message to see if user successfully loginned"""
        if choice == "1":
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

        """Send REGISTER request and check received message to see if user successfully registered"""
        if choice == "2":
            client.send(f"REGISTER {username} {password}\n".encode("utf-8"))
            line, buffer = read_line(client, buffer)
            if line is None:# Close connection if not receive any message
                print(">> Server closed connection during registration.")
                client.close()
                sys.exit(1)

            print(f">> Phản hồi đăng ký: {line}")# Print the register announcement

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
