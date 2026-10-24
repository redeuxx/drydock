"""In-memory failed-login limiter, keyed on username plus IP and on IP alone."""

import threading
import time
from collections import OrderedDict, deque

WINDOW_SECONDS = 15 * 60
MAX_PER_USER_IP = 10
MAX_PER_IP = 50
MAX_KEYS = 10_000


class LoginRateLimiter:
    def __init__(self) -> None:
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _keys(username: str, ip: str) -> tuple[tuple[str, int], tuple[str, int]]:
        return (f"u\0{username.lower()}\0{ip}", MAX_PER_USER_IP), (f"i\0{ip}", MAX_PER_IP)

    def _recent(self, key: str, now: float) -> deque[float]:
        entries = self._failures.get(key, deque())
        while entries and entries[0] <= now - WINDOW_SECONDS:
            entries.popleft()
        return entries

    def blocked(self, username: str, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return any(
                len(self._recent(key, now)) >= limit for key, limit in self._keys(username, ip)
            )

    def failure(self, username: str, ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key, limit in self._keys(username, ip):
                entries = self._recent(key, now)
                entries.append(now)
                while len(entries) > limit:
                    entries.popleft()
                self._failures[key] = entries
                self._failures.move_to_end(key)
            while len(self._failures) > MAX_KEYS:
                self._failures.popitem(last=False)

    def reset(self, username: str, ip: str) -> None:
        with self._lock:
            self._failures.pop(self._keys(username, ip)[0][0], None)
