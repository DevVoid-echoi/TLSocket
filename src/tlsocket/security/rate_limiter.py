import time
from collections import defaultdict


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        threshold = now - self.window_seconds
        history = [t for t in self._history[key] if t >= threshold]

        if len(history) >= self.max_events:
            self._history[key] = history
            return False

        history.append(now)
        self._history[key] = history
        return True

    def forget(self, key: str) -> None:
        self._history.pop(key, None)

    def reset(self) -> None:
        self._history.clear()