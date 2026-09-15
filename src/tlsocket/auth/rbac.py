class Permission:
    CHAT = "CHAT"
    KICK = "KICK"
    BAN = "BAN"
    UNBAN = "UNBAN"
    SET = "SET"

ROLES_PERMISSIONS = {
    "admin": {
        Permission.CHAT,
        Permission.KICK,
        Permission.BAN,
        Permission.UNBAN,
        Permission.SET
    },
    "moderator": {
        Permission.CHAT,
        Permission.KICK,
        Permission.BAN,
        Permission.UNBAN
    },
    "user": {
        Permission.CHAT
    }
}

def has_permission(role:str, permission:str) -> bool:
    user_perms = ROLES_PERMISSIONS.get(role, set())
    return permission in user_perms

    