import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass
class Session:
    username: str
    role: str


class ClientRegistry:
    def __init__(self, max_connections_per_ip: int) -> None:
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._max_connections_per_ip = max_connections_per_ip

        self._sessions: dict[Any, Session] = {}
        self._by_name: dict[str, Any] = {}
        self._client_ips: dict[Any, str] = {}
        self._ip_counts: defaultdict[str, int] = defaultdict(int)
        self._pending_logins: set[str] = set()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def try_reserve_ip_slot(self, client_socket, ip: str) -> bool:
        with self._lock:
            if self._ip_counts[ip] >= self._max_connections_per_ip:
                return False
            self._ip_counts[ip] += 1
            self._client_ips[client_socket] = ip
            return True

    def release_ip_slot(self, client_socket, fallback_ip: str | None = None) -> None:
        with self._lock:
            ip = self._client_ips.pop(client_socket, None) or fallback_ip
            if ip and ip in self._ip_counts:
                self._ip_counts[ip] -= 1
                if self._ip_counts[ip] <= 0:
                    del self._ip_counts[ip]

    def add(self, client_socket, session: Session) -> None:
        with self._lock:
            self._sessions[client_socket] = session
            self._by_name[session.username] = client_socket
            self._pending_logins.discard(session.username)

    def remove(self, client_socket) -> Session | None:
        with self._lock:
            session = self._sessions.pop(client_socket, None)
            if session is not None:
                if self._by_name.get(session.username) is client_socket:
                    del self._by_name[session.username]
            return session

    def get_session(self, client_socket) -> Session | None:
        with self._lock:
            return self._sessions.get(client_socket)

    def by_name(self, username: str):
        with self._lock:
            return self._by_name.get(username)

    def snapshot(self):
        with self._lock:
            return list(self._sessions.keys())

    def reserve_username(self, username: str) -> bool:
        with self._lock:
            if username in self._by_name or username in self._pending_logins:
                return False
            self._pending_logins.add(username)
            return True

    def release_reservation(self, username: str) -> None:
        with self._lock:
            self._pending_logins.discard(username)

    def set_role(self, username: str, new_role: str):
        with self._lock:
            sock = self._by_name.get(username)
            if sock is None:
                return None
            self._sessions[sock].role = new_role
            return sock

    def send(self, client_socket, message: bytes) -> bool:
        try:
            with self._send_lock:
                client_socket.sendall(message)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False

    def broadcast(self, message: bytes, sender=None) -> list:
        failed = []
        for client_socket in self.snapshot():
            if client_socket is sender:
                continue
            if not self.send(client_socket, message):
                failed.append(client_socket)
        return failed

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._by_name.clear()
            self._client_ips.clear()
            self._ip_counts.clear()
            self._pending_logins.clear()
    