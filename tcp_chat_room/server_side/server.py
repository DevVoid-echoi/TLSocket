import threading
import socket
import os
import sys
import ssl

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BAN_FILE_PATH = os.path.join(BASE_DIR, "data", "ban.txt")
CERT_FILE_PATH = os.path.join(PARENT_DIR, "certs", "server.crt")
KEY_FILE_PATH = os.path.join(PARENT_DIR, "certs", "server.key")

from config import HOST, PORT
from handlers.lock import state_lock
from handlers.ban_handler import get_banned_users, add_ban, remove_ban
from handlers.client_handler import clients, nicknames, read_line, broadcast, kick_user, handle_messages, clean_up_client, user_sessions, accept_new_client, rekey_client_ip
from auth.authentication import login, register, set_user_role
from logs_management.record_logs import log_event, brute_force_detector, log_test_event
from security.brute_force_detection import BruteForceDetector

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE_PATH, keyfile=KEY_FILE_PATH)

TEST_MODE = False  # Set to True to enable test mode for IP address overriding

"""Connect using IPv4 and TCP"""
raw_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
raw_server_socket.bind((HOST, PORT))
raw_server_socket.listen()

def receive():
    """Receive message from clients"""
    while True:
        try:
            raw_client, address = raw_server_socket.accept()

        except OSError:
            break

        print(f"Connected with {str(address)}")
        real_ip_addr = address[0]
        ip_addr = real_ip_addr

        if not accept_new_client(raw_client, real_ip_addr):
            continue

        try:
            client = context.wrap_socket(raw_client, server_side=True)
            rekey_client_ip(raw_client, client)
        except ssl.SSLError as e:
            print(f"[TLS ERROR] SSL error occurred: {e}")
            clean_up_client(raw_client, "TLS_HANDSHAKE_FAILED", client_ip=real_ip_addr)
            continue
        except OSError as e:
            print(f"[ERROR] Socket error during TLS Handshake with {address}: {e}")
            clean_up_client(raw_client, "SOCKET_ERROR", client_ip=real_ip_addr)
            continue

        log_event("USER_CONNECTED", ip=ip_addr)

        try:
            buffer = ""
            session = None

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
                        client.send("ERR PERMISSION_DENIED.\n".encode("utf-8"))
                    continue
                
                if brute_force_detector.is_ip_blocked(ip_addr):
                    remaining_time = brute_force_detector.get_remaining_ban_time(ip_addr)
                    print(f"[SECURITY] Refused connection from blocked IP: {ip_addr} ({remaining_time}s remaining)")
                    client.send(f"ERR RATE_LIMIT_EXCEEDED Blocked due to brute-force attempts. Try again in {remaining_time}s.\n".encode("utf-8"))
                    log_event("RATE_LIMIT_EXCEEDED", username="Unknown", ip=ip_addr, extra_info=f"reason=BRUTE_FORCE_DETECTION remaining_sec={remaining_time}")
                    break

                if line.startswith("LOGIN "):
                    parts = line.split(" ", 2)
                    if len(parts) == 3:
                        _, username, password = parts
                        username = username.strip().lower()
                        already_online = False

                        # Check whether the username has been used
                        with state_lock:
                            if username in nicknames:
                                already_online = True
                        
                        if already_online:
                            client.send("ERR ALREADY_LOGGED_IN\n".encode("utf-8"))
                            log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=ALREADY_LOGGED_IN")
                            continue

                        success, user_session = login(username, password)
                        if success and user_session:
                            if username in get_banned_users():
                                client.send("ERR BANNED\n".encode('utf-8'))
                                log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=BANNED")
                                continue
                            session = user_session
                            log_event("LOGIN_SUCCESS", username=username, ip=ip_addr)
                        elif success and not user_session:
                            client.send("ERR BANNED\n".encode('utf-8'))
                            log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=BANNED")
                            continue
                        else:
                            client.send("ERR WRONG_AUTH\n".encode("utf-8")) # Decline due to wrong information
                            log_event("LOGIN_FAILED", username=username, ip=ip_addr)
                            continue
                    else:
                        client.send("ERR INVALID_FORMAT\n".encode("utf-8"))
                        continue
                # Register new users
                elif line.startswith("REGISTER "):
                    parts = line.split(" ", 2)
                    if len(parts) == 3:
                        _, username, password = parts
                        success, msg = register(username, password)
                        if success:
                            client.send(f"OK {msg}\n".encode("utf-8")) # Send OK message if succeess
                            log_event("REGISTER_SUCCESS", username=username, ip=ip_addr)
                        else:
                            client.send(f"ERR {msg}\n".encode("utf-8")) # Show error message
                            log_event("REGISTER_FAILED", username=username, ip=ip_addr, extra_info=f"reason={msg}")
                    else:
                        client.send("ERR INVALID_FORMAT\n".encode("utf-8"))
                        log_event("REGISTER_FAILED", username="Unknown", ip=ip_addr, extra_info="reason=INVALID_FORMAT")
                    continue
                else:
                    client.send("ERR INVALID_COMMAND\n".encode("utf-8"))
                    log_event("LOGIN_FAILED", username="Unknown", ip=ip_addr, extra_info="reason=INVALID_COMMAND")
                    continue
        
            # --- Check if session is valid ---
            if not session:
                try:
                    clean_up_client(client, "AUTHENTICATION_FAILED", client_ip=real_ip_addr)
                except:
                    pass
                continue
                    
            nickname = session["username"]

            with state_lock:
                clients.append(client)
                nicknames.append(nickname)
                user_sessions[client] = session

            # --- Succeed and start threads ---
            print(f"User '{nickname}' ({session['role']}) connected successfully!")
            client.send(f"OK Connected as {nickname}, role:{session['role']}\n".encode("utf-8"))
            broadcast(f"MSG {nickname} joined the chat!\n".encode("utf-8"), sender=client)

            thread = threading.Thread(target=handle_messages, args=(client, real_ip_addr), daemon=True)
            thread.start()
        
        except (OSError, ConnectionResetError, BrokenPipeError) as e:
            print(f"[ERROR] Connection error with {address}: {e}")
            log_event("CONNECTION_ERROR", username="Unknown", ip=real_ip_addr, extra_info=f"error={e}")
            try:
                clean_up_client(client, "CONNECTION_ERROR", client_ip=real_ip_addr)
            except:
                pass
            continue

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
                    broadcast(f"MSG {target_user} is now an '{new_role}!\n".encode('utf-8')) # Send the announcement to all users
                    log_event("SET", username=target_user, extra_info=f"new_role={new_role}") 

                    target_sock = None
                    with state_lock:
                        for sock, sess in user_sessions.items():
                            if sess.get("username") == target_user:
                                sess["role"] = new_role
                                target_sock = sock
                                break

                    if target_sock:
                        try:
                            target_sock.send(f"MSG {'-' * 50}\n".encode("utf-8"))
                            target_sock.send(f"MSG [SYSTEM] Your role has been updated to '{new_role}' by Server Admin!\n".encode("utf-8"))
                            if new_role in ["moderator", "admin"]:
                                target_sock.send(f"MSG {'-' * 50}\n".encode("utf-8"))
                                target_sock.send(f"MSG [SYSTEM] New commands unlocked:\n".encode("utf-8"))
                                target_sock.send(f"MSG - Type '/kick' <user_name> to kick a user out of the chat room\n".encode("utf-8"))
                                target_sock.send(f"MSG - Type '/ban' <user_name> to ban a user from the chat room\n".encode("utf-8"))
                                target_sock.send(f"MSG - Type '/unban' <user_name> to unban a user\n".encode("utf-8"))
                                if new_role == "admin":
                                    target_sock.send(f"MSG - Type '/set' <username> <role> to set a new role for a user\n".encode("utf-8"))
                            target_sock.send(f"MSG {'-' * 50}\n".encode("utf-8"))

                        except OSError as e:
                            print(f"[SERVER CONSOLE] Error sending role update to '{target_user}': {e}")
                            pass
                else:
                    print(f"[SERVER CONSOLE] Failed: User '{target_user}' not found.")
            elif cmd.startswith("/kick "):
                target_user = cmd[6:].strip().lower()
                if kick_user(target_user):
                    broadcast(f"MSG {target_user} was kicked by server admin!\n".encode('utf-8')) # Send the announcement to all users
                    print(f'{target_user} was kicked!')
                    log_event("KICK", username=target_user, extra_info=f"by=server_admin")
            elif cmd.startswith("/ban "):
                target_user = cmd[5:].strip().lower()
                if kick_user(target_user):
                    broadcast(f"MSG {target_user} was banned by server admin!\n".encode('utf-8')) # Send the announcement to all users
                    add_ban(target_user)
                    print(f'{target_user} was banned!')
                    log_event("BAN", username=target_user, extra_info=f"by=server_admin")
            elif cmd.startswith("/unban "):
                target_user = cmd[7:].strip().lower()
                remove_ban(target_user)
                print(f'{target_user} was unbanned!')
                broadcast(f"MSG {target_user} was unbanned by server admin!\n".encode('utf-8')) # Send the announcement to all users
                log_event("UNBAN", username=target_user, extra_info=f"by=server_admin")

        except (EOFError, KeyboardInterrupt):
            break

if __name__ == "__main__":
    try:
        print(f"[TLS SERVER] Listening on {HOST}:{PORT}...")
        console_threading = threading.Thread(target=server_console_input, daemon=True)
        console_threading.start()
        receive()
    except KeyboardInterrupt:
        print("\nServer is shutting down...")
        with state_lock:
            for client in clients:
                try:
                    client.close()
                except OSError:
                    pass

            clients.clear()
            nicknames.clear()
            user_sessions.clear()

            raw_server_socket.close()
            sys.exit()
