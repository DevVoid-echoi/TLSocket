import socket
import ssl
import sys
import threading

from tlsocket.auth.authentication import login, register, set_user_role
from tlsocket.config import CERT_FILE, HOST, KEY_FILE, MAX_REGISTER_ATTEMPTS, PORT, REGISTER_WINDOW
from tlsocket.protocol import ErrorCode, chat_message, error, ok
from tlsocket.security.rate_limiter import SlidingWindowLimiter
from tlsocket.server_side.client_registry import Session
from tlsocket.server_side.handlers.ban_handler import (
    add_ban,
    get_banned_users,
    remove_ban,
)
from tlsocket.server_side.handlers.client_handler import (
    accept_new_client,
    broadcast,
    clean_up_client,
    handle_messages,
    kick_user,
    read_line,
    registry,
)
from tlsocket.server_side.logs_management.record_logs import (
    brute_force_detector,
    log_event,
    log_test_event,
)

TEST_MODE = False  # Set to True to enable test mode for IP address overriding

register_limiter = SlidingWindowLimiter(max_events=MAX_REGISTER_ATTEMPTS, window_seconds=REGISTER_WINDOW)

class ChatServer:
    def __init__(self, host: str | None = None, port: int | None = None) -> None:
        self.host = host if host is not None else HOST
        self.port = port if port is not None else PORT
        self.context: ssl.SSLContext | None = None
        self.socket: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None

    def start(self) -> int:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]

        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        return self.port

    def _accept_loop(self) -> None:
        while True:
            try:
                raw_client, address = self.socket.accept()
            except OSError:
                break
            print(f"Connected with {address}")
            threading.Thread(
                target=handle_new_connection,
                args=(raw_client, address, self.context),
                daemon=True,
            ).start()

    def stop(self) -> None:
        if self.socket is not None:
            self.socket.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)

    def wait(self) -> None:
        if self._accept_thread is not None:
            self._accept_thread.join()

def handle_new_connection(raw_client, address, context):
    """Handle a new client connection, perform authentication, and start message handling."""
    real_ip_addr = address[0]
    ip_addr = real_ip_addr
        
    client = None
    try:
        client = context.wrap_socket(raw_client, server_side=True)
    except ssl.SSLError as e:
        print(f"[TLS ERROR] SSL error occurred: {e}")
        clean_up_client(raw_client, "TLS_HANDSHAKE_FAILED", client_ip=real_ip_addr)
        return
    except OSError as e:
        print(f"[ERROR] Socket error during TLS Handshake with {address}: {e}")
        clean_up_client(raw_client, "SOCKET_ERROR", client_ip=real_ip_addr)
        return
    
    if not accept_new_client(client, real_ip_addr):
        try:
            client.sendall(error(ErrorCode.CONNECTION_LIMIT_REACHED).encode())
        except OSError:
            pass
        log_event("CONNECTION_LIMIT_REACHED", extra_info=f"ip={real_ip_addr}")
        try:
            client.close()
        except OSError:
            pass
        return

    log_event("USER_CONNECTED", ip=ip_addr)

    try:
        buffer = ""
        session = None

        reserved_username = None

        # --- AUTHENTICATION ---
        while not session:
            line, buffer = read_line(client, buffer)
            if not line:
                break

            if line.startswith("CLIENT_IP "):
                if TEST_MODE:
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        ip_addr = parts[1].strip()
                        # print(f"[TEST MODE] Real IP {real_ip_addr} overridden with Fake IP: {ip_addr}")
                        log_test_event("USER_CONNECTED", ip=ip_addr, extra_info=f"real_ip={real_ip_addr}")
                else: 
                    client.sendall(error(ErrorCode.PERMISSION_DENIED).encode())
                continue
                
            if brute_force_detector.is_ip_blocked(ip_addr):
                remaining_time = brute_force_detector.get_remaining_ban_time(ip_addr)
                print(f"[SECURITY] Refused connection from blocked IP: {ip_addr} ({remaining_time}s remaining)")
                client.sendall(error(ErrorCode.RATE_LIMIT_EXCEEDED, f"Blocked due to brute-force attempts. Try again in {remaining_time}s.").encode())
                log_event("RATE_LIMIT_EXCEEDED", username="Unknown", ip=ip_addr, extra_info=f"reason=BRUTE_FORCE_DETECTION remaining_sec={remaining_time}")
                break

            if line.startswith("LOGIN "):
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    _, username, password = parts
                    username = username.strip().lower()
                    already_online = not registry.reserve_username(username)
                    if not already_online:
                        reserved_username = username

                    if already_online:
                        client.sendall(error(ErrorCode.ALREADY_LOGGED_IN).encode())
                        log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=ALREADY_LOGGED_IN")
                        reserved_username = None
                        continue

                    success, user_session = login(username, password)
                    if success and user_session:
                        if username in get_banned_users():
                            registry.release_reservation(reserved_username)
                            reserved_username = None
                            client.sendall(error(ErrorCode.BANNED).encode())
                            log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=BANNED")
                            continue
                        session = user_session
                        log_event("LOGIN_SUCCESS", username=username, ip=ip_addr)
                    elif success and not user_session:
                        registry.release_reservation(reserved_username)
                        reserved_username = None
                        client.sendall(error(ErrorCode.BANNED).encode())
                        log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=BANNED")
                        continue
                    else:
                        registry.release_reservation(reserved_username)
                        reserved_username = None
                        client.sendall(error(ErrorCode.WRONG_AUTH).encode()) # Decline due to wrong information
                        log_event("LOGIN_FAILED", username=username, ip=ip_addr)
                        continue
                else:
                    client.sendall(error(ErrorCode.INVALID_FORMAT).encode())
                    continue
            # Register new users
            elif line.startswith("REGISTER "):
                if not register_limiter.allow(ip_addr):
                    client.sendall(error(ErrorCode.RATE_LIMIT_EXCEEDED, "ERR RATE_LIMIT_EXCEEDED Too many registration attempts. Try again later!").encode())
                    log_event("RATE_LIMIT_EXCEEDED", username="Unknown", ip=ip_addr, extra_info="reason=REGISTER_FLOOD")
                    continue
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    _, username, password = parts
                    success, msg = register(username, password)
                    if success:
                        client.sendall(ok(f"{msg}").encode()) # Send OK message if succeess
                        log_event("REGISTER_SUCCESS", username=username, ip=ip_addr)
                    else:
                        client.sendall(f"ERR {msg}\n".encode()) # Show error message
                        log_event("REGISTER_FAILED", username=username, ip=ip_addr, extra_info=f"reason={msg}")
                else:
                    client.sendall(error(ErrorCode.INVALID_FORMAT).encode())
                    log_event("REGISTER_FAILED", username="Unknown", ip=ip_addr, extra_info="reason=INVALID_FORMAT")
                continue
            else:
                client.sendall(error(ErrorCode.INVALID_COMMAND).encode())
                # Protocol errors are not credential-guessing: log them, but keep
                # them out of brute-force scoring (which only reacts to LOGIN_FAILED).
                log_event("INVALID_COMMAND", username="Unknown", ip=ip_addr, extra_info="reason=INVALID_COMMAND")
                continue
        
        # --- Check if session is valid ---
        if not session:
            try:
                clean_up_client(client, "AUTHENTICATION_FAILED", client_ip=real_ip_addr)
            except Exception: # nosec B110 - best-effort cleanup, không có gì để retry ở bước xác thực thất bại
                pass
            return
                
        nickname = session["username"]

        nickname = session["username"]
        registry.add(client, Session(username=nickname, role=session["role"]))
        reserved_username = None

        # --- Succeed and start threads ---
        print(f"User '{nickname}' ({session['role']}) connected successfully!")
        client.sendall(f"OK Connected as {nickname}, role:{session['role']}\n".encode())
        broadcast(chat_message(f"{nickname} joined the chat!").encode(), sender=client)

        thread = threading.Thread(target=handle_messages, args=(client, real_ip_addr), daemon=True)
        thread.start()
        
    except (OSError, ConnectionResetError, BrokenPipeError) as e:
        print(f"[ERROR] Connection error with {address}: {e}")
        log_event("CONNECTION_ERROR", username="Unknown", ip=real_ip_addr, extra_info=f"error={e}")
        try:
            clean_up_client(client, "CONNECTION_ERROR", client_ip=real_ip_addr)
        except Exception: # nosec B110 - best-effort cleanup khi đang xử lý lỗi kết nối, không retry được nữa
            pass
        return

    finally:
        if reserved_username is not None:
            registry.release_reservation(reserved_username)

def server_console_input():
    while True:
        try:
            cmd = input().strip()
            if cmd.startswith("/set "):
                parts = cmd[5:].strip().split()
                if len(parts) < 2:
                    print("[SERVER CONSOLE] Usage: /set <username> <role> (e.g. /set alice moderator)")
                    continue
                target_user = parts[0].strip().lower()
                new_role = parts[1].strip().lower()

                if set_user_role(target_user, new_role):
                    print(f"[SERVER CONSOLE] Success: User '{target_user}' is now an '{new_role}'!")
                    broadcast(chat_message(f"{target_user} is now an '{new_role}!").encode()) # Send the announcement to all users
                    log_event("SET", username=target_user, extra_info=f"new_role={new_role}") 

                    target_sock = registry.set_role(target_user, new_role)

                    if target_sock:
                        try:
                            target_sock.sendall(chat_message('-' * 50).encode())
                            target_sock.sendall(chat_message(f"[SYSTEM] Your role has been updated to '{new_role}' by Server Admin!").encode())
                            if new_role in ["moderator", "admin"]:
                                target_sock.sendall(chat_message('-' * 50).encode())
                                target_sock.sendall(chat_message("[SYSTEM] New commands unlocked:").encode())
                                target_sock.sendall(chat_message("- Type '/kick' <user_name> to kick a user out of the chat room").encode())
                                target_sock.sendall(chat_message("- Type '/ban' <user_name> to ban a user from the chat room").encode())
                                target_sock.sendall(chat_message("- Type '/unban' <user_name> to unban a user").encode())
                                if new_role == "admin":
                                    target_sock.send(chat_message("- Type '/set' <username> <role> to set a new role for a user").encode())
                            target_sock.sendall(chat_message('-' * 50).encode())

                        except OSError as e:
                            print(f"[SERVER CONSOLE] Error sending role update to '{target_user}': {e}")
                            pass
                else:
                    print(f"[SERVER CONSOLE] Failed: User '{target_user}' not found.")
            elif cmd.startswith("/kick "):
                target_user = cmd[6:].strip().lower()
                if kick_user(target_user):
                    broadcast(chat_message(f"{target_user} was kicked by server admin!").encode()) # Send the announcement to all users
                    print(f'{target_user} was kicked!')
                    log_event("KICK", username=target_user, extra_info="by=server_admin")
            elif cmd.startswith("/ban "):
                target_user = cmd[5:].strip().lower()
                add_ban(target_user)
                kick_user(target_user)  # Disconnect the user if they are currently online
                broadcast(chat_message(f"{target_user} was banned by server admin!").encode()) # Send the announcement to all users
                print(f'{target_user} was banned!')
                log_event("BAN", username=target_user, extra_info="by=server_admin")
            elif cmd.startswith("/unban "):
                target_user = cmd[7:].strip().lower()
                remove_ban(target_user)
                print(f'{target_user} was unbanned!')
                broadcast(chat_message(f"{target_user} was unbanned by server admin!").encode()) # Send the announcement to all users
                log_event("UNBAN", username=target_user, extra_info="by=server_admin")

        except (EOFError, KeyboardInterrupt):
            break

def main():
    server = ChatServer()
    port = server.start()
    print(f"[TLS SERVER] Listening on {HOST}:{port}...")
    threading.Thread(target=server_console_input, daemon=True).start()
    try:
        server.wait()
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        for client in registry.snapshot():
            try:
                client.close()
            except OSError:
                pass
        registry.reset()

        server.stop()
        sys.exit()


if __name__ == "__main__":
    main()
