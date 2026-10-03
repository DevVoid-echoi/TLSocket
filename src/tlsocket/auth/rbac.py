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

ROLE_RANK = {
    "user": 0,
    "moderator": 1,
    "admin": 2
}

def has_permission(role:str, permission:str) -> bool:
    user_perms = ROLES_PERMISSIONS.get(role, set())
    return permission in user_perms

def can_act_on(actor_role: str, target_role: str) -> bool:
    return ROLE_RANK.get(actor_role, -1) > ROLE_RANK.get(target_role, -1)

    