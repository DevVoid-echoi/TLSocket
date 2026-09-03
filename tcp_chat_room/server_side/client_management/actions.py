from server_side.client_management.lock import state_lock
from server_side.client_management.ban_handler import add_ban, remove_ban
from auth.rbac import has_permission, Permission
from server_side.logs_management.record_logs import log_event
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY_DIR = os.path.join(BASE_DIR, "security")
AUTH_DIR = os.path.join(BASE_DIR, "auth")

from security.validation import validate_message, parse_and_validate_command
from auth.authentication import set_user_role

clients = []
nicknames = []
user_sessions = {}

def read_line(sock, buffer):
    """Read full-line messages"""
    while not "\n" in buffer:
        try:
            chunk = sock.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                return None, buffer
            buffer += chunk
        except(ConnectionResetError, BrokenPipeError, OSError):
            return None, buffer

    line, buffer = buffer.split("\n", 1)
    return line.strip(), buffer

def clean_up_client(client, disconnect_msg):
    """Clean up disconnected users"""
    with state_lock:
            if client in clients:
                index = clients.index(client)
                nickname = nicknames.pop(index)
                clients.pop(index)
            else:
                nickname = None
            
            user_sessions.pop(client, None)

    try:
        client.close()
    except OSError:
        pass

    if nickname: # Print annoucement that the disconnected user left the chat
        print(f"Client {nickname} {disconnect_msg}!")
        broadcast(f"MSG {nickname} left the chat!\n",sender=client)
        log_event("USER_DISCONNECTED", username=nickname)


def broadcast(message, sender=None):
    """Broadcast the message to all other users"""
    if isinstance(message, str):
        message = message.encode("utf-8") # Encode the message

    with state_lock:
        targets = list(clients) # Get the list of user

    disconnected_clients = []

    for client in targets:
        if client != sender:
            try:
                client.sendall(message) # Send the message to all users except for the sender
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print(f"Error sending message: {e}")
                disconnected_clients.append(client) # Disconnect the user if get an error while sending the message
    for client in disconnected_clients:
        clean_up_client(client, "disconnected") # Clean up the disconnected client

def kick_user(name):
    """Remove the user in kick command"""
    client_to_kick = None
    with state_lock:
        if name in nicknames:
            index = nicknames.index(name)
            client_to_kick = clients.pop(index)
            nicknames.pop(index)
            user_sessions.pop(client_to_kick, None)

    if client_to_kick:
        try:
            # Print the kick announcement and close the connection of the kicked user
            client_to_kick.send("MSG You were kicked!\n".encode("utf-8"))
            client_to_kick.close()
        except Exception:
            pass

def handle_messages(client):
    """Handle received messages from users"""
    buffer = ""
    while True:
        line, buffer = read_line(client, buffer)
        """Clean up disconnected user if not receive any message"""
        if line is None:
            clean_up_client(client, "disconnected")
            break
        
        if len(line) > 2000:
            client.send("ERR MESSAGE_TOO_LONG\n".encode("utf-8"))
            continue

        session = user_sessions.get(client)
        if not session:
            client.send("ERR NOT_AUTHENTICATED\n".encode("utf-8"))
            break

        user_role = session.get("role", "user")

        with state_lock:
            current_nick = (
                nicknames[clients.index(client)] if client in clients
                else None
            )

        if not current_nick:
            break

        if line.startswith(("KICK ", "BAN ", "UNBAN ", "SET ")):
            cmd, args, err = parse_and_validate_command(line)

            if err != "OK":
                client.send(f"ERR {err}\n".encode("utf-8"))
                log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd={cmd} {err}")
                continue

            # Check if the user is admin and remove the target user
            if line.startswith('KICK '):
                if not has_permission(user_role, Permission.KICK):
                    client.send("MSG PERMISSION_DENIED: You do not have KICK permission.\n".encode("utf-8"))
                    log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd=KICK_PERMISSION_DENIED")
                    continue

                name_to_kick = line[5:].strip()
                if name_to_kick:
                    kick_user(name_to_kick)
                    broadcast(f"MSG {name_to_kick} was kicked by {current_nick}!\n".encode('utf-8')) # Send the announcement to all users
                    log_event("KICK", username=name_to_kick, extra_info=f"by={current_nick}")
                continue
            # Check if the user is admin and ban the target user
            elif line.startswith('BAN '):
                if not has_permission(user_role, Permission.BAN):
                    client.send("MSG PERMISSION_DENIED: You do not have BAN permission.\n".encode("utf-8"))
                    log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd=BAN_PERMISSION_DENIED")
                    continue

                name_to_ban = line[4:].strip()
                if name_to_ban:
                    add_ban(name_to_ban)
                    kick_user(name_to_ban)
                    broadcast(f"MSG {name_to_ban} was kicked by {current_nick}!\n".encode('utf-8')) # Send the announcement to all users
                    print(f'{name_to_ban} was banned!')
                    log_event("BAN", username=name_to_ban, extra_info=f"by={current_nick}")

                continue
            elif line.startswith("UNBAN "):
                if not has_permission(user_role, Permission.UNBAN):
                    client.send("MSG PERMISSION DENIED: You do not have UNBAN permission.\n".encode("utf-8"))
                    log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd=UNBAN_PERMISSION_DENIED")
                    continue

                target_user = line[6:].strip()
                remove_ban(target_user)
                print(f'{target_user} was unbanned!')
                log_event("UNBAN", username=target_user, extra_info=f"by={current_nick}")
            elif line.startswith("SET "):
                if not has_permission(user_role, Permission.SET):
                    client.send("MSG PERMISSION DENIED: You do not have SET permission.\n".encode("utf=8"))
                    log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd=SET_PERMISSION_DENIED")
                    continue

                parts = line[4:].strip().split(maxsplit=1)
                target_user = parts[0].strip().lower()
                new_role = parts[1].strip().lower()

                if set_user_role(target_user, new_role):
                    print(f"{target_user} role has been changed to {new_role} by {current_nick}")
                    broadcast(f"MSG {target_user} role has been changed to {new_role} by {current_nick}\n".encode("utf-8"))
                    if new_role in ["moderator", "admin"]:
                        target_client.send(f"MSG {'-' * 50}\n".encode("utf-8"))
                        target_client.send(f"MSG [SYSTEM] New commands unlocked:\n".encode("utf-8"))
                        target_client.send(f"MSG - Type '/kick' <user_name> to kick a user out of the chat room\n".encode("utf-8"))
                        target_client.send(f"MSG - Type '/ban' <user_name> to ban a user from the chat room\n".encode("utf-8"))
                        target_client.send(f"MSG - Type '/unban' <user_name> to unban a user\n".encode("utf-8"))
                        if new_role == "admin":
                            target_client.send(f"MSG - Type '/set' <username> <role> to set a new role for a user\n".encode("utf-8"))
                        target_client.send(f"MSG {'-' * 50}\n".encode("utf-8"))
                    log_event("SET_ROLE", username=target_user, extra_info=f"by={current_nick} new_role={new_role}")

                    with state_lock:
                        if target_user in nicknames:
                            index = nicknames.index(target_user)
                            target_client = clients[index]
                            if target_client in user_sessions:
                                user_sessions[target_client]["role"] = new_role
                else:
                    client.send(f"ERR INVALID_ROLE: Role '{new_role}' is invalid.\n".encode("utf-8"))
                    log_event("INVALID_COMMAND", username=current_nick, extra_info=f"cmd=SET_INVALID_ROLE new_role={new_role}")

        """Broadcast the normal message"""
        if line.startswith("MSG "):
            content = line[4:]
            valid, err_msg = validate_message(content)

            if not valid:
                client.send(f"ERR {err_msg}\n".encode("utf-8"))
                log_event("INVALID_MESSAGE", username=current_nick, extra_info=f"msg={content} {err_msg}")
                continue

            broadcast(f"MSG {current_nick}: {content}\n".encode("utf-8"), sender=client)
