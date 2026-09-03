import sys
from auth.rbac import has_permission, Permission

def print_instructions(nickname, user_role = "user"):
    """Print instructions for users and special instructions for admin"""
    print("-" * 50)
    print(" CHAT INSTRUCTIONS:")
    print(" - Enter a message and press Enter to send.")
    print(" - Type '/quit' or '/exit' to leave the chat room.")
    if has_permission(user_role, Permission.KICK):
        print(" - Type '/kick' <user_name> to kick a user out of the chat room")
    if has_permission(user_role, Permission.BAN):
        print(" - Type '/ban' <user_name> to ban a user from the chat room")
    if has_permission(user_role, Permission.UNBAN):
        print(" - Type '/unban' <user_name> to unban a user")
    if has_permission(user_role, Permission.SET):
        print(" - Type '/set' <username> <role> to set a new role for a user")
    print("-" * 50)
