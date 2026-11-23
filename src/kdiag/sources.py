"""Evidence source abstraction. Adapters implement this protocol; all methods are read-only."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from .models import (
    ContainerLog,
    EventEvidence,
    JobEvidence,
    NodeEvidence,
    PodEvidence,
    PvcEvidence,
    ReadFailure,
    ServiceEvidence,
    Target,
    WorkloadRef,
    WorkloadStatus,
)


class SourceError(Exception):
    def __init__(self, reason: ReadFailure, detail: str | None = None, retryable: bool = False):
        super().__init__(reason)
        self.reason: ReadFailure = reason
        self.detail = detail
        self.retryable = retryable


class EvidenceSource(Protocol):
    """Read-only. Implementations authorise server-side and never expose credentials.

    Adapters must honour `limit` by paginating: the collector can only trim what it receives.
    """

    async def find_workloads(self, target: Target) -> list[WorkloadRef]: ...

    async def get_workload_status(self, ref: WorkloadRef) -> WorkloadStatus: ...

    async def list_pods(self, ref: WorkloadRef, limit: int) -> list[PodEvidence]: ...

    async def list_events(
        self, ref: WorkloadRef, pod_names: Sequence[str], limit: int
    ) -> list[EventEvidence]: ...

    async def get_nodes(self, names: Sequence[str]) -> list[NodeEvidence]: ...

    async def list_pvcs(self, ref: WorkloadRef, names: Sequence[str]) -> list[PvcEvidence]: ...

    async def list_services(
        self, ref: WorkloadRef, pods: Sequence[PodEvidence]
    ) -> list[ServiceEvidence]: ...

    async def list_jobs(self, ref: WorkloadRef) -> list[JobEvidence]: ...

    async def get_namespace_phase(self, namespace: str) -> str: ...

    async def get_logs(
        self, ref: WorkloadRef, pod: str, container: str, previous: bool,
        tail_lines: int, limit_bytes: int,
    ) -> ContainerLog: ...
