import socket
import ssl
import sys
import threading

from tlsocket.client_side.client_management.connection import (
    read_line,
    receive,
    write,
)
from tlsocket.client_side.client_management.instructions import print_instructions
from tlsocket.config import CERT_FILE, CLIENT_HOST, PORT
from tlsocket.protocol import Command, format_command


def main():
    """Connect using IPv4 and TCP then wrap the socket with SSL context"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(str(CERT_FILE))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    raw_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client = context.wrap_socket(raw_client, server_hostname=CLIENT_HOST)
        client.connect((CLIENT_HOST, PORT))
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
                client.send(format_command(Command.LOGIN, username, password).encode())
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
                client.send(format_command(Command.REGISTER, username, password).encode())
                line, buffer = read_line(client, buffer)
                if line is None:# Close connection if not receive any message
                    print(">> Server closed connection during registration.")
                    client.close()
                    sys.exit(1)

                print(f">> Phản hồi đăng ký: {line}")# Print the register announcement
            except Exception:
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
