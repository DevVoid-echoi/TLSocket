import threading
import socket
import os
import sys

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from config import HOST, PORT, SCRIPT_DIR, BAN_FILE_PATH
from client_management.lock import state_lock
from client_management.ban_handler import get_banned_users, add_ban
from client_management.actions import clients, nicknames, read_line, broadcast, kick_user, handle_messages, clean_up_client, user_sessions
from auth.authentication import login, register, set_user_role
from logs_management.record_logs import log_event

"""Connect using IPv4 and TCP"""
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

def receive():
    """Receive message from clients"""
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}") # Kết nối với client ở địa chỉ "address"
        ip_addr = address[0]

        log_event("USER_CONNECTED", ip=ip_addr)

        buffer = ""
        session = None

        # --- AUTHENTICATION ---
        while not session:
            line, buffer = read_line(client, buffer)
            if not line:
                break
            
            """Check for valid login information"""
            if line.startswith("LOGIN "):
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    _, username, password = parts
                    success, user_session = login(username, password)
                    if success and user_session:
                        session = user_session
                        log_event("LOGIN_SUCCESS", username=username, ip=ip_addr)
                    elif success and not user_session:
                        client.send("ERR BANNED\n".encode('utf-8'))
                        log_event("LOGIN_FAILED", username=username, ip=ip_addr, extra_info="reason=BANNED")
                        client.close()
                        continue
                    else:
                        client.send("ERR WRONG_AUTH\n".encode("utf-8")) # Decline due to wrong information
                        log_event("LOGIN_FAILED", username=username, ip=ip_addr)
                        continue
                else:
                    client.send("ERR INVALID_FORMAT\n".encode("utf-8"))
                    continue

            """Register new users"""
            if line.startswith("REGISTER "):
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    _, username, password = parts
                    success, msg = register(username, password)
                    if success:
                        client.send(f"OK {msg}\n".encode("utf-8")) # Send OK message if succeess
                        log_event("REGISTER_SUCCESS", username=username, ip=ip_addr)
                    else:
                        client.send(f"ERR {msg}\n".encode("utf-8")) # Show error message
                else:
                    client.send("ERR INVALID_FORMAT\n".encode("utf-8"))
                continue
        
        # Nếu không có session (Client chủ động ngắt kết nối)
        if not session:
            client.close()
            continue
                
        nickname = session["username"]

        # --- Check connect conditions ---
        # Check whether the username has been used
        with state_lock:
            if nickname in nicknames:
                client.send("ERR ALREADY_LOGGED_IN\n".encode("utf-8"))
                log_event("LOGIN_FAILED", username=nickname, ip=ip_addr, extra_info="reason=ALREDY_LOGGED_IN")
                client.close()
                continue

        # Check if the user is banned
        banned_users = get_banned_users()
        if nickname in banned_users:
            client.send("ERR BANNED\n".encode('utf-8'))
            log_event("LOGIN_FAILED", username=nickname, ip=ip_addr, extra_info="reason=BANNED")
            client.close()
            continue

        with state_lock:
            clients.append(client)
            nicknames.append(nickname)
            user_sessions[client] = session

        # --- Succeed and start threads ---
        print(f"User '{nickname}' ({session['role']}) connected successfully!")
        client.send(f"OK Connected as {nickname}, role:{session['role']}\n".encode("utf-8"))
        broadcast(f"MSG {nickname} joined the chat!\n".encode("utf-8"), sender=client)

        thread = threading.Thread(target=handle_messages, args=(client,), daemon=True)
        thread.start()

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
                    log_event("SET", username=target_user, extra_info=f"new_role={new_role}") 

                    with state_lock:
                        if target_user in nicknames:
                            index = nicknames.index(target_user)
                            user_sock = clients[index]
                            if user_sock in user_sessions:
                                user_sessions[user_sock]["role"] = new_role
                                user_sock.send(f"MSG [SYSTEM] Your role has been updated to '{new_role}' by Server Admin!\n".encode("utf-8"))
                                if new_role == "admin":
                                    user_sock.send("MSG [SYSTEM] New commands unlocked:\n".encode("utf-8"))
                                    user_sock.send("MSG [SYSTEM] You have been granted '{role}' role by Server Admin!\n".encode("utf-8"))
                                    user_sock.send("MSG - Type '/kick' <user_name> to kick a user out of the chat room\n".encode("utf-8"))
                                    user_sock.send("MSG - Type '/ban' <user_name> to ban a user from the chat room\n".encode("utf-8"))
                else:
                    print(f"[SERVER CONSOLE] Failed: User '{target_user}' not found.")

        except (EOFError, KeyboardInterrupt):
            break

try:
    print(f"Server is running on {HOST}:{PORT}...")
    console_threading = threading.Thread(target=server_console_input, daemon=True)
    console_threading.start()
    receive()
except KeyboardInterrupt:
    print("\nServer is shutting down...")
    for client in clients:
        client.close()
    server.close()
    sys.exit()
