from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Client-side limiter so one diagnosis cannot hammer an API server."""

    def __init__(self, rate_per_s: float, burst: int) -> None:
        if rate_per_s <= 0 or burst < 1:
            raise ValueError("rate_per_s must be > 0 and burst >= 1")
        self._rate, self._burst = rate_per_s, float(burst)
        self._tokens, self._last = float(burst), time.monotonic()
        self._lock = asyncio.Lock()

    def try_acquire(self) -> float:
        """Non-blocking: 0.0 if a token was taken, else seconds until one is available."""
        now = time.monotonic()
        self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
        self._last = now
        if self._tokens >= 1:
            self._tokens -= 1
            return 0.0
        return (1 - self._tokens) / self._rate

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = (1 - self._tokens) / self._rate
            await asyncio.sleep(wait)
