from tlsocket.auth.authentication import set_user_role
from tlsocket.auth.rbac import Permission, has_permission
from tlsocket.config import (
    MAX_CONNECTIONS_PER_IP,
    MAX_LINE_LENGTH,
    MAX_MESSAGES_PER_WINDOW,
    MESSAGE_RATE_WINDOW,
)
from tlsocket.security.rate_limiter import SlidingWindowLimiter
from tlsocket.security.validation import parse_and_validate_command, validate_message
from tlsocket.server_side.client_registry import ClientRegistry
from tlsocket.server_side.handlers.ban_handler import add_ban, remove_ban
from tlsocket.server_side.logs_management.record_logs import log_event

registry = ClientRegistry(max_connections_per_ip=MAX_CONNECTIONS_PER_IP)
message_limiter = SlidingWindowLimiter(max_events=MAX_MESSAGES_PER_WINDOW, window_seconds=MESSAGE_RATE_WINDOW)

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

def accept_new_client(client_socket, client_ip):
    return registry.try_reserve_ip_slot(client_socket, client_ip)

def clean_up_client(client, disconnect_msg, client_ip=None):
    """Clean up disconnected users"""
    session = registry.remove(client)
    message_limiter.forget(client)
    registry.release_ip_slot(client, fallback_ip=client_ip)

    try:
        client.close()
    except OSError:
        pass

    if session: # Print annoucement that the disconnected user left the chat
        print(f"Client {session.username} {disconnect_msg}!")
        broadcast(f"MSG {session.username} left the chat!\n",sender=client)
        log_event("USER_DISCONNECTED", username=session.username)


def broadcast(message, sender=None):
    """Broadcast the message to all other users"""
    if isinstance(message, str):
        message = message.encode("utf-8") # Encode the message

    for failed_client in registry.broadcast(message, sender=sender):
        clean_up_client(failed_client, "disconnected") # Clean up the disconnected client

def kick_user(name):
    """Remove the user in kick command"""
    client_to_kick = registry.by_name(name)
    if not client_to_kick:
        return False

    registry.send(client_to_kick, b"MSG You were kicked!\n")
    clean_up_client(client_to_kick, "kicked")
    return True
    
def handle_messages(client, client_ip=None):
    """Handle received messages from users"""
    buffer = ""
    while True:
        line, buffer = read_line(client, buffer)
        """Clean up disconnected user if not receive any message"""
        if line is None:
            clean_up_client(client, "disconnected", client_ip)
            break
        
        if len(line) > 2000:
            client.send(b"ERR MESSAGE_TOO_LONG\n")
            continue

        session = registry.get_session(client)
        if not session:
            client.send(b"ERR NOT_AUTHENTICATED\n")
            clean_up_client(client, "disconnected", client_ip)
            break

        user_role = session.role
        current_nick = session.username

        if line.startswith(("KICK ", "BAN ", "UNBAN ", "SET ")):
            cmd, args, err = parse_and_validate_command(line)

            if err != "OK":
                client.send(f"ERR {err}\n".encode())
                log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd={cmd} {err}")
                continue

            # Check if the user is admin and remove the target user
            if line.startswith('KICK '):
                if not has_permission(user_role, Permission.KICK):
                    client.send(b"MSG PERMISSION_DENIED: You do not have KICK permission.\n")
                    log_event("INVALID_COMMAND", username=current_nick, extra_info="cmd=KICK_PERMISSION_DENIED")
                    continue

                name_to_kick = line[5:].strip()
                if name_to_kick:
                    if kick_user(name_to_kick):
                        broadcast(f"MSG {name_to_kick} was kicked by {current_nick}!\n".encode()) # Send the announcement to all users
                        print(f'{name_to_kick} was kicked!')
                        log_event("KICK", username=name_to_kick, extra_info=f"by={current_nick}")
                continue
            # Check if the user is admin and ban the target user
            elif line.startswith('BAN '):
                if not has_permission(user_role, Permission.BAN):
                    client.send(b"MSG PERMISSION_DENIED: You do not have BAN permission.\n")
                    log_event("INVALID_COMMAND", username=current_nick, extra_info="cmd=BAN_PERMISSION_DENIED")
                    continue

                name_to_ban = line[4:].strip()
                if name_to_ban:
                    add_ban(name_to_ban)
                    if kick_user(name_to_ban):
                        broadcast(f"MSG {name_to_ban} was banned by {current_nick}!\n".encode()) # Send the announcement to all users
                        print(f'{name_to_ban} was banned!')
                        log_event("BAN", username=name_to_ban, extra_info=f"by={current_nick}")

                continue
            elif line.startswith("UNBAN "):
                if not has_permission(user_role, Permission.UNBAN):
                    client.send(b"MSG PERMISSION DENIED: You do not have UNBAN permission.\n")
                    log_event("INVALID_COMMAND", username=current_nick, extra_info="cmd=UNBAN_PERMISSION_DENIED")
                    continue

                target_user = line[6:].strip()
                remove_ban(target_user)
                print(f'{target_user} was unbanned!')
                log_event("UNBAN", username=target_user, extra_info=f"by={current_nick}")
                continue
            elif line.startswith("SET "):
                if not has_permission(user_role, Permission.SET):
                    client.send(b"MSG PERMISSION DENIED: You do not have SET permission.\n")
                    log_event("INVALID_COMMAND", username=current_nick, extra_info="cmd=SET_PERMISSION_DENIED")
                    continue

                parts = line[4:].strip().split(maxsplit=1)
                if len(parts) != 2:
                    client.send(b"ERR INVALID_FORMAT: Usage: SET <username> <role>\n")
                    continue
                target_user = parts[0].strip().lower()
                new_role = parts[1].strip().lower()

                if set_user_role(target_user, new_role):
                    print(f"{target_user} role has been changed to {new_role} by {current_nick}")
                    broadcast(f"MSG {target_user} role has been changed to {new_role} by {current_nick}\n".encode())
                    target_client = registry.set_role(target_user, new_role)
                    if target_client:
                        if new_role in ["moderator", "admin"]:
                            target_client.send(f"MSG {'-' * 50}\n".encode())
                            target_client.send(b"MSG [SYSTEM] New commands unlocked:\n")
                            target_client.send(b"MSG - Type '/kick' <user_name> to kick a user out of the chat room\n")
                            target_client.send(b"MSG - Type '/ban' <user_name> to ban a user from the chat room\n")
                            target_client.send(b"MSG - Type '/unban' <user_name> to unban a user\n")
                            if new_role == "admin":
                                target_client.send(b"MSG - Type '/set' <username> <role> to set a new role for a user\n")
                            target_client.send(f"MSG {'-' * 50}\n".encode())
                    log_event("SET_ROLE", username=target_user, extra_info=f"by={current_nick} new_role={new_role}")

                else:
                    client.send(f"ERR INVALID_ROLE: Role '{new_role}' is invalid.\n".encode())
                    log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd=SET_INVALID_ROLE new_role={new_role}")

        """Broadcast the normal message"""
        if line.startswith("MSG "):
            if not message_limiter.allow(client):
                client.send(b"ERR RATE_LIMIT_EXCEEDED Typing too fast. Try again later!\n")
                log_event("RATE_LIMIT_EXCEEDED", username=current_nick, extra_info="reason=MESSAGE_FLOOD")
                continue

            content = line[4:]
            valid, err_msg = validate_message(content)

            if not valid:
                client.send(f"ERR {err_msg}\n".encode())
                log_event("INVALID_MESSAGE", username=current_nick, extra_info=f"msg={content} {err_msg}")
                continue

            broadcast(f"MSG {current_nick}: {content}\n".encode(), sender=client)
