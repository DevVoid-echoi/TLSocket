import ssl
import sys
import threading

from tlsocket.client_side.client_management.connection import (
    ServerRejectedError,
    connect_with_backoff,
    read_line,
    receive,
    write,
)
from tlsocket.client_side.client_management.instructions import print_instructions
from tlsocket.config import CERT_FILE, CLIENT_HOST, PORT
from tlsocket.protocol import Command, format_command


def main():
    """Connect using IPv4 and TCP then wrap the socket with SSL context"""
    try:
        client = connect_with_backoff(CLIENT_HOST, PORT, CERT_FILE)
    except ServerRejectedError as e:
        print(f"Connection refused: {e.detail}")
        sys.exit(1)
    except (ssl.SSLError, OSError) as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    buffer = ""
    nickname = None
    user_role = "user"

    """Print Register/Login options"""
    print("=== CHAT SYSTEM AUTHENTICATION ===")
    while nickname is None:
        choice = input("Choose (1: Login, 2: Register): ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        command = Command.LOGIN if choice == "1" else Command.REGISTER

        try:
            client.send(format_command(command, username, password).encode())
            line, buffer = read_line(client, buffer)
        except OSError:
            line = None

        if line is None: # Close connection if not receive any message
            print(">> Server closed connection - Retrying...")
            try:
                client = connect_with_backoff(CLIENT_HOST, PORT, CERT_FILE)
                buffer = ""
            except ServerRejectedError as e:
                print(f"Connection refused: {e.detail}")
                sys.exit(1)
            continue

        if choice == "1":
            if line.startswith("OK"): # If succcessfully login, print the announcement and set nickname = username
                print(">> Login successfully!")
                nickname = username
                if "role:" in line:
                    user_role = line.split("role:")[1].strip()
            else: # Show any login error
                print(f">> Login error: {line}")
        else:
            print(f">> Register announcement: {line}")# Print the register announcement

    print_instructions(nickname, user_role) # Print instructions based on the role of user

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
