import socket
import ssl
import sys
import time

from tlsocket.config import MAX_LINE_LENGTH
from tlsocket.protocol import Command, chat_message, format_command


class ServerRejectedError(Exception):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail

def connect(host: str, port: int, cert_file) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(str(cert_file))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = context.wrap_socket(raw,server_hostname=host)
    client.connect((host,port))

    client.settimeout(0.2)
    line, _ = read_line(client, "")
    client.settimeout(None)
    if line is not None:
        client.close()
        detail = line[4:] if line.startswith("ERR ") else line
        raise ServerRejectedError(detail)

    return client

def connect_with_backoff(
        host: str, port: int, cert_file, max_retries: int = 5, base_delay: float = 1.0
) -> ssl.SSLSocket:
    delay = base_delay
    for attempt in range(1, max_retries + 1):
        try:
            return connect(host, port, cert_file)
        except ServerRejectedError as e:
            if attempt == max_retries:
                raise
            print(f">> {e.detail} - thử lại sau {delay: .0f}s ({attempt}/{max_retries})")
            time.sleep(delay)
            delay = min(delay * 2, 30)
    raise AssertionError("unreachable")

stop_threads = False

def read_line(sock, buffer):
    """Read full-line messages"""
    while "\n" not in buffer:
        if len(buffer) > MAX_LINE_LENGTH:
            return None, buffer
        try:
            chunk = sock.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                return None, buffer
            buffer += chunk
        except(ConnectionResetError, BrokenPipeError, OSError):
            return None, buffer

    line, buffer = buffer.split("\n", 1)
    return line.strip(), buffer

def receive(client, nickname):
    """Handle different types of received messages"""
    global stop_threads
    buffer = ""
    while not stop_threads:
        line, buffer = read_line(client, buffer)
        """Close connection if not receive any message"""
        if line is None:
            sys.stdout.write("\r\033[KServer closed connection.\n")
            sys.stdout.flush()
            stop_threads = True
            client.close()
            break

        """Print the message if received normal message"""    
        if line.startswith("MSG "):
            msg = line[4:]
            sys.stdout.write(f"\r\033[K{msg}\n")
            sys.stdout.write(f"{nickname}: ")
            sys.stdout.flush()
            continue
        
        """Disconnect if reveived error messages"""
        if line.startswith("ERR "):
            err = line[4:]
            sys.stdout.write(f"\r\033[K[Error] {err}\n")
            sys.stdout.flush()
            stop_threads = True
            break
            

def write(client, nickname):
    """Handle different types of user input"""
    global stop_threads
    while not stop_threads:
        try:
            user_input = input(f"{nickname}: ")

            if not user_input:
                continue
            
            cmd = user_input.strip()

            # Disconnect when receive quit/exit command
            if cmd.lower() in ["/quit", "/exit"]:
                stop_threads = True
                sys.stdout.write("\r\033[KDisconnecting from server...\n")
                sys.stdout.flush()
                client.close()
                break
            # Send KICK command to the server for permission validation
            elif cmd.lower().startswith("/kick "):
                target_user = cmd[6:].strip()
                if not target_user:
                    print("Usage: /kick <username>")
                    continue
                client.send(format_command(Command.KICK, target_user).encode())
                continue
            # Send BAN command to the server for permission validation
            elif cmd.lower().startswith("/ban "):
                target_user = cmd[5:].strip()
                if not target_user:
                    print("Usage: /ban <username>")
                    continue
                client.send(format_command(Command.BAN, target_user).encode())
                continue
            elif cmd.lower().startswith("/unban "):
                target_user = cmd[7:].strip()
                if not target_user:
                    print("Usage: /unban <username>")
                    continue
                client.send(format_command(Command.UNBAN, target_user).encode())
            elif cmd.lower().startswith("/set "):
                parts = cmd[5:].strip().split(maxsplit=1)
                if len(parts) != 2:
                    print("Usage: /set <username> <role>")
                    continue
                target_user = parts[0].strip().lower()
                new_role = parts[1].strip().lower()
                client.send(format_command(Command.SET, target_user, new_role).encode())
            elif cmd:
                client.send(chat_message(user_input).encode())

        except (KeyboardInterrupt, EOFError):
            """Allow quit from keyboard and disconnect when receive an error"""
            stop_threads = True
            sys.stdout.write("\r\033[K[!] Exiting via keyboard shortcut...\n")
            sys.stdout.flush()
            client.close()
            break

        except Exception as e:
            """Handle all exceptions"""
            sys.stdout.write(f"\r\033[KError: {e}\n")
            sys.stdout.flush()
            break