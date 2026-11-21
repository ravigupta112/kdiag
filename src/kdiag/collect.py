"""Bounded, timeout-controlled collection. Every failure becomes a PartialReadError."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TypeVar

from .mask import mask_text
from .models import (
    EventEvidence,
    Evidence,
    Limits,
    PartialReadError,
    PodEvidence,
    WorkloadRef,
)
from .sources import EvidenceSource, SourceError

T = TypeVar("T")
_HEALTHY = {"Running", "Succeeded"}


class Collector:
    def __init__(self, src: EvidenceSource, limits: Limits):
        self._src = src
        self._limits = limits
        self._sem = asyncio.Semaphore(limits.concurrency)
        self.errors: list[PartialReadError] = []

    async def call(self, resource: str, fn: Callable[[], Awaitable[T]]) -> T | None:
        try:
            async with self._sem:
                async with asyncio.timeout(self._limits.request_timeout_s):
                    return await fn()
        except TimeoutError:
            self.errors.append(PartialReadError(resource=resource, reason="timeout", retryable=True))
        except SourceError as exc:
            self.errors.append(PartialReadError(
                resource=resource,
                reason=exc.reason,
                retryable=exc.retryable,
                detail=mask_text(exc.detail),
            ))
        except Exception:  # noqa: BLE001 - never leak exception text; it may carry credentials
            self.errors.append(PartialReadError(resource=resource, reason="error"))
        return None

    async def collect(self, ref: WorkloadRef) -> Evidence:
        lim = self._limits
        available: set[str] = set()
        truncated = False

        # Fetch up to a ceiling, then select: truncating at the source could drop the failing pod.
        pods = await self.call(
            "pods", lambda: self._src.list_pods(ref, lim.max_pods_fetched + 1))
        pod_list: list[PodEvidence] = []
        if pods is not None:
            available.add("pods")
            if len(pods) > lim.max_pods:
                truncated = True  # includes the case where the fetch ceiling itself was hit
            # failing pods first, then by name: deterministic under truncation
            pod_list = sorted(pods, key=lambda p: (p.phase in _HEALTHY, p.name))[: lim.max_pods]

        names = [p.name for p in pod_list]
        events = await self.call(
            "events", lambda: self._src.list_events(ref, names, lim.max_events_fetched + 1))
        event_list: list[EventEvidence] = []
        if events is not None:
            available.add("events")
            if len(events) > lim.max_events:
                truncated = True
            floor = datetime.min.replace(tzinfo=UTC)
            event_list = sorted(
                events, key=lambda e: e.timestamp or floor, reverse=True)[: lim.max_events]

        return Evidence(
            pods=tuple(pod_list), events=tuple(event_list), available=frozenset(available),
            partial_errors=tuple(self.errors), truncated=truncated,
        )
