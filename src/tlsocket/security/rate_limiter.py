import threading
import time
from collections import defaultdict


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._history: dict[object, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: object) -> bool:
        now = time.monotonic()
        threshold = now - self.window_seconds
        with self._lock:
            history = [t for t in self._history[key] if t >= threshold]

            if len(history) >= self.max_events:
                self._history[key] = history
                return False

            history.append(now)
            self._history[key] = history
            return True

    def forget(self, key: object) -> None:
        with self._lock:
            self._history.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._history.clear()