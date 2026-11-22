"""In-memory EvidenceSource for tests and examples."""
from __future__ import annotations

import asyncio
from collections.abc import Sequence

from .models import EventEvidence, PodEvidence, Target, WorkloadRef, WorkloadStatus
from .sources import SourceError


class FakeSource:
    def __init__(
        self,
        workloads: list[WorkloadRef],
        pods: list[PodEvidence] | None = None,
        events: list[EventEvidence] | None = None,
        fail: dict[str, SourceError] | None = None,
        delay: dict[str, float] | None = None,
        status: WorkloadStatus | None = None,
    ):
        self.status = status
        self.workloads, self.pods, self.events = workloads, pods or [], events or []
        self.fail, self.delay = fail or {}, delay or {}
        self.calls: list[str] = []

    async def _gate(self, name: str) -> None:
        self.calls.append(name)
        if name in self.delay:
            await asyncio.sleep(self.delay[name])
        if name in self.fail:
            raise self.fail[name]

    async def find_workloads(self, target: Target) -> list[WorkloadRef]:
        await self._gate("find_workloads")
        return [w for w in self.workloads
                if w.name == target.name and w.kind == target.kind
                and (target.namespace is None or w.namespace == target.namespace)]

    async def get_workload_status(self, ref: WorkloadRef) -> WorkloadStatus:
        await self._gate("get_workload_status")
        if self.status is not None:
            return self.status
        n = len([p for p in self.pods if p.namespace == ref.namespace])
        return WorkloadStatus(generation=1, observed_generation=1, replicas=n, updated_replicas=n,
                              ready_replicas=n, available_replicas=n)

    async def list_pods(self, ref: WorkloadRef, limit: int) -> list[PodEvidence]:
        await self._gate("list_pods")
        return [p for p in self.pods if p.namespace == ref.namespace][:limit]

    async def list_events(
        self, ref: WorkloadRef, pod_names: Sequence[str], limit: int
    ) -> list[EventEvidence]:
        await self._gate("list_events")
        return self.events[:limit]
