import queue
import socket
import ssl
import threading
from collections import defaultdict
from dataclasses import dataclass

from tlsocket.config import SEND_QUEUE_MAXSIZE


@dataclass
class Session:
    username: str
    role: str

class _ClientWriter:
    def __init__(self, sock: ssl.SSLSocket) -> None:
        self.sock = sock
        self.queue: queue.Queue[bytes | None] = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            while True:
                item = self.queue.get()
                if item is None:
                    return
                try:
                    self.sock.sendall(item)
                except OSError:
                    break
        finally:
            try:
                self.sock.close()
            except OSError:
                pass

    def enqueue(self, message: bytes) -> bool:
        try:
            self.queue.put_nowait(message)
            return True
        except queue.Full:
            return False

    def stop(self) -> None:
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

class ClientRegistry:
    def __init__(self, max_connections_per_ip: int) -> None:
        self._lock = threading.Lock()
        self._max_connections_per_ip = max_connections_per_ip

        self._sessions: dict[ssl.SSLSocket, Session] = {}
        self._by_name: dict[str, ssl.SSLSocket] = {}
        self._client_ips: dict[ssl.SSLSocket, str] = {}
        self._ip_counts: defaultdict[str, int] = defaultdict(int)
        self._pending_logins: set[str] = set()
        self._writers: dict[ssl.SSLSocket, _ClientWriter] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def try_reserve_ip_slot(self, client_socket: ssl.SSLSocket, ip: str) -> bool:
        with self._lock:
            if self._ip_counts[ip] >= self._max_connections_per_ip:
                return False
            self._ip_counts[ip] += 1
            self._client_ips[client_socket] = ip
            return True

    def release_ip_slot(self, client_socket: ssl.SSLSocket) -> None:
        with self._lock:
            ip = self._client_ips.pop(client_socket, None)
            if ip is None:
                return
            if ip and ip in self._ip_counts:
                self._ip_counts[ip] -= 1
                if self._ip_counts[ip] <= 0:
                    del self._ip_counts[ip]

    def add(self, client_socket: ssl.SSLSocket, session: Session) -> None:
        with self._lock:
            self._sessions[client_socket] = session
            self._by_name[session.username] = client_socket
            self._pending_logins.discard(session.username)
            self._writers[client_socket] = _ClientWriter(client_socket)

    def remove(self, client_socket: ssl.SSLSocket) -> Session | None:
        with self._lock:
            session = self._sessions.pop(client_socket, None)
            writer = self._writers.pop(client_socket, None)
            if session is not None:
                if self._by_name.get(session.username) is client_socket:
                    del self._by_name[session.username]
        if writer:
            writer.stop()
        return session

    def get_session(self, client_socket: ssl.SSLSocket) -> Session | None:
        with self._lock:
            return self._sessions.get(client_socket)

    def by_name(self, username: str) -> ssl.SSLSocket | None:
        with self._lock:
            return self._by_name.get(username)

    def snapshot(self) -> list[ssl.SSLSocket]:
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

    def set_role(self, username: str, new_role: str) -> ssl.SSLSocket | None:
        with self._lock:
            sock = self._by_name.get(username)
            if sock is None:
                return None
            self._sessions[sock].role = new_role
            return sock

    def send(self, client_socket: ssl.SSLSocket, message: bytes) -> bool:
        with self._lock:
            writer = self._writers.get(client_socket)
        if writer is None:
            return False
        return writer.enqueue(message)

    def broadcast(self, message: bytes, sender: ssl.SSLSocket | None = None) -> list[ssl.SSLSocket]:
        failed: list[ssl.SSLSocket] = []
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
            self._writers.clear()
    