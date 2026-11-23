from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable

from ..models import DiagnosisReport

Key = tuple[str, ...]


def cache_key(tenant: str, cluster: str, namespace: str | None, kind: str, name: str,
              job_id: str | None, logs: bool, scope: str = "all") -> Key:
    """Tenant is always first, so one tenant can never hit another's entry. `scope` identifies which
    namespaces the caller may see, so an unscoped search never shares results across differently
    privileged users of the same tenant."""
    return (tenant, cluster, namespace or "", kind, name, job_id or "",
            "logs" if logs else "nologs", scope)


class TTLCache:
    """Entries expire by TTL, are evicted LRU by count and by total bytes, and can be invalidated."""

    def __init__(self, max_entries: int, ttl_s: float, max_bytes: int = 16_000_000,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._data: OrderedDict[Key, tuple[float, int, DiagnosisReport]] = OrderedDict()
        self._max, self._ttl, self._max_bytes, self._clock = max_entries, ttl_s, max_bytes, clock
        self._bytes = 0

    def get(self, key: Key) -> DiagnosisReport | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, _, value = item
        if self._clock() >= expires:
            self._drop(key)
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: Key, value: DiagnosisReport) -> None:
        size = len(value.model_dump_json())
        if size > self._max_bytes:
            return  # a single oversize entry is never cached
        self._drop(key)
        self._data[key] = (self._clock() + self._ttl, size, value)
        self._bytes += size
        while len(self._data) > self._max or self._bytes > self._max_bytes:
            self._drop(next(iter(self._data)))

    def _drop(self, key: Key) -> None:
        item = self._data.pop(key, None)
        if item:
            self._bytes -= item[1]

    def invalidate(self, match: Callable[[Key], bool]) -> int:
        doomed = [k for k in self._data if match(k)]
        for k in doomed:
            self._drop(k)
        return len(doomed)

    def clear(self) -> None:
        self._data.clear()
        self._bytes = 0

    def __len__(self) -> int:
        return len(self._data)

    @property
    def size_bytes(self) -> int:
        return self._bytes
