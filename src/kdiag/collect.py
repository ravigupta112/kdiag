"""Bounded, timeout-controlled collection. Every failure becomes a PartialReadError.

State accumulates on the instance, so if the overall deadline fires midway the evidence
gathered so far is still available through snapshot().
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TypeVar

from .models import (
    EventEvidence,
    Evidence,
    Limits,
    PartialReadError,
    PodEvidence,
    WorkloadRef,
    WorkloadStatus,
)
from .sources import EvidenceSource, SourceError
from .timeutil import to_utc

T = TypeVar("T")


def _failing(p: PodEvidence) -> bool:
    """True if the pod looks unhealthy. Phase alone is not enough: a crash-looping pod is Running."""
    if p.phase == "Succeeded":
        return False
    if p.phase != "Running":
        return True
    return any(
        (not c.ready and not c.is_init) or c.waiting_reason is not None or c.restart_count > 0
        for c in p.containers
    )


class Collector:
    def __init__(self, src: EvidenceSource, limits: Limits):
        self._src = src
        self._limits = limits
        self._sem = asyncio.Semaphore(limits.concurrency)
        self.errors: list[PartialReadError] = []
        self._pods: list[PodEvidence] = []
        self._events: list[EventEvidence] = []
        self._workload: WorkloadStatus | None = None
        self._available: set[str] = set()
        self._truncated = False

    async def call(self, resource: str, fn: Callable[[], Awaitable[T]]) -> T | None:
        try:
            async with self._sem:
                async with asyncio.timeout(self._limits.request_timeout_s):
                    return await fn()
        except TimeoutError:
            self.errors.append(PartialReadError(resource=resource, reason="timeout", retryable=True))
        except SourceError as exc:
            self.errors.append(PartialReadError(
                resource=resource, reason=exc.reason, retryable=exc.retryable, detail=exc.detail))
        except Exception:  # noqa: BLE001 - never leak exception text; it may carry credentials
            self.errors.append(PartialReadError(resource=resource, reason="error"))
        return None

    async def collect(self, ref: WorkloadRef) -> Evidence:
        lim = self._limits
        # Fetch up to a ceiling, then select: truncating at the source could drop the failing pod.
        ws, pods = await asyncio.gather(
            self.call("workload_status", lambda: self._src.get_workload_status(ref)),
            self.call("pods", lambda: self._src.list_pods(ref, lim.max_pods_fetched + 1)),
        )
        if ws is not None:
            self._workload = ws
            self._available.add("workload")
        if pods is not None:
            self._available.add("pods")
            if len(pods) > lim.max_pods:
                self._truncated = True  # includes the case where the fetch ceiling itself was hit
            self._pods = sorted(pods, key=lambda p: (not _failing(p), p.name))[: lim.max_pods]

        names = [p.name for p in self._pods]
        events = await self.call(
            "events", lambda: self._src.list_events(ref, names, lim.max_events_fetched + 1))
        if events is not None:
            self._available.add("events")
            if len(events) > lim.max_events:
                self._truncated = True
            floor = datetime.min.replace(tzinfo=UTC)
            self._events = sorted(
                events, key=lambda e: to_utc(e.timestamp) or floor, reverse=True)[: lim.max_events]
        return self.snapshot()

    def snapshot(self) -> Evidence:
        return Evidence(
            pods=tuple(self._pods), events=tuple(self._events), workload=self._workload,
            available=frozenset(self._available), partial_errors=tuple(self.errors),
            truncated=self._truncated,
        )
