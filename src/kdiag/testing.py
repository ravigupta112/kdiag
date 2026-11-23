"""In-memory EvidenceSource for tests and examples."""
from __future__ import annotations

import asyncio
from collections.abc import Sequence

from .models import (
    ContainerLog,
    EventEvidence,
    JobEvidence,
    NodeEvidence,
    PodEvidence,
    PvcEvidence,
    ServiceEvidence,
    Target,
    WorkloadRef,
    WorkloadStatus,
)
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
        nodes: list[NodeEvidence] | None = None,
        pvcs: list[PvcEvidence] | None = None,
        services: list[ServiceEvidence] | None = None,
        jobs: list[JobEvidence] | None = None,
        logs: list[ContainerLog] | None = None,
        namespace_phase: str = "Active",
    ):
        self.workloads, self.pods, self.events = workloads, pods or [], events or []
        self.fail, self.delay = fail or {}, delay or {}
        self.status = status
        self.nodes, self.pvcs, self.services = nodes or [], pvcs or [], services or []
        self.jobs, self.logs, self.namespace_phase = jobs or [], logs or [], namespace_phase
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

    async def get_nodes(self, names: Sequence[str]) -> list[NodeEvidence]:
        await self._gate("get_nodes")
        return [n for n in self.nodes if n.name in set(names)]

    async def list_pvcs(self, ref: WorkloadRef, names: Sequence[str]) -> list[PvcEvidence]:
        await self._gate("list_pvcs")
        return [p for p in self.pvcs if p.name in set(names)]

    async def list_services(
        self, ref: WorkloadRef, pods: Sequence[PodEvidence]
    ) -> list[ServiceEvidence]:
        await self._gate("list_services")
        return list(self.services)

    async def list_jobs(self, ref: WorkloadRef) -> list[JobEvidence]:
        await self._gate("list_jobs")
        return list(self.jobs)

    async def get_namespace_phase(self, namespace: str) -> str:
        await self._gate("get_namespace_phase")
        return self.namespace_phase

    async def get_logs(
        self, ref: WorkloadRef, pod: str, container: str, previous: bool,
        tail_lines: int, limit_bytes: int,
    ) -> ContainerLog:
        await self._gate("get_logs")
        for lg in self.logs:
            if (lg.pod, lg.container, lg.previous) == (pod, container, previous):
                return ContainerLog(pod=pod, container=container, previous=previous,
                                    lines=lg.lines[-tail_lines:])
        raise SourceError("not_found")
