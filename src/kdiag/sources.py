"""Evidence source abstraction. The Kubernetes adapter (Phase 2) implements this protocol."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from .models import (
    EventEvidence,
    PodEvidence,
    ReadFailure,
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
    """Read-only. Implementations must authorise server-side and never expose credentials."""

    async def find_workloads(self, target: Target) -> list[WorkloadRef]: ...

    async def get_workload_status(self, ref: WorkloadRef) -> WorkloadStatus: ...

    async def list_pods(self, ref: WorkloadRef, limit: int) -> list[PodEvidence]: ...

    async def list_events(
        self, ref: WorkloadRef, pod_names: Sequence[str], limit: int
    ) -> list[EventEvidence]: ...
