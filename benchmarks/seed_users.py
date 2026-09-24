import json
import sys
from pathlib import Path

from argon2 import PasswordHasher

n = int(sys.argv[1])
h = PasswordHasher().hash("pw123")
out = Path("bench_data")
out.mkdir(exist_ok=True)
users = {f"user{i}": {"password_hash": h, "role": "user"} for i in range (n)}
(out / "user.json").write_text(json.dumps(users))
print(f"seeded {n} users -> {out / 'user.json'}")