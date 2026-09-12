import pytest

from tlsocket.auth.rbac import Permission, has_permission

ALL_PERMS = [Permission.CHAT, 
            Permission.KICK,
            Permission.BAN,
            Permission.UNBAN,
            Permission.SET]

MATRIX = {
    "admin": dict.fromkeys(ALL_PERMS, True),
    "moderator": {
        p: (p != Permission.SET) for p in ALL_PERMS
    },
    "user": {p: (p == Permission.CHAT) for p in ALL_PERMS},
}

@pytest.mark.parametrize("role", list(MATRIX))
@pytest.mark.parametrize("perm", ALL_PERMS)
def test_permission_matrix(role, perm):
    assert has_permission(role, perm) is MATRIX[role][perm]

def test_unknown_role_has_no_permission():
    for p in [Permission.CHAT,
              Permission.KICK,
              Permission.BAN,
              Permission.UNBAN,
              Permission.SET]:
        assert has_permission("root", p) is False
        assert has_permission("", p) is False

    