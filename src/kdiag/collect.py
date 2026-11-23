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
    ContainerLog,
    EventEvidence,
    Evidence,
    JobEvidence,
    Limits,
    NodeEvidence,
    PartialReadError,
    PodEvidence,
    PvcEvidence,
    ServiceEvidence,
    WorkloadRef,
    WorkloadStatus,
)
from .sources import EvidenceSource, SourceError
from .timeutil import to_utc

T = TypeVar("T")
_NO_LOGS_YET = {"ImagePullBackOff", "ErrImagePull", "ContainerCreating", "PodInitializing",
                "InvalidImageName", "CreateContainerConfigError", "ErrImageNeverPull"}


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


def log_targets(pods: list[PodEvidence], limit: int) -> list[tuple[str, str, bool]]:
    """(pod, container, previous): restarted containers get previous logs, others current."""
    out: list[tuple[str, str, bool]] = []
    for p in pods:
        for c in p.containers:
            if c.ready and c.restart_count == 0:
                continue
            if c.restart_count == 0 and c.waiting_reason in _NO_LOGS_YET:
                continue  # never started: there are no logs to read
            out.append((p.name, c.name, c.restart_count > 0))
    return out[:limit]


class Collector:
    def __init__(self, src: EvidenceSource, limits: Limits, collect_logs: bool = False):
        self._src = src
        self._limits = limits
        self._collect_logs = collect_logs
        self._sem = asyncio.Semaphore(limits.concurrency)
        self.errors: list[PartialReadError] = []
        self._pods: list[PodEvidence] = []
        self._events: list[EventEvidence] = []
        self._nodes: list[NodeEvidence] = []
        self._pvcs: list[PvcEvidence] = []
        self._services: list[ServiceEvidence] = []
        self._jobs: list[JobEvidence] = []
        self._logs: list[ContainerLog] = []
        self._ns_phase: str | None = None
        self._workload: WorkloadStatus | None = None
        self._available: set[str] = set()
        self._truncated = False

    async def call(
        self, resource: str, fn: Callable[[], Awaitable[T]], ignore_not_found: bool = False,
        optional: bool = False,
    ) -> T | None:
        try:
            async with self._sem:
                async with asyncio.timeout(self._limits.request_timeout_s):
                    return await fn()
        except TimeoutError:
            self.errors.append(PartialReadError(
                resource=resource, reason="timeout", retryable=True, optional=optional))
        except SourceError as exc:
            if not (ignore_not_found and exc.reason == "not_found"):
                self.errors.append(PartialReadError(
                    resource=resource, reason=exc.reason, retryable=exc.retryable,
                    optional=optional and exc.reason in ("forbidden", "not_found"),
                    detail=exc.detail))
        except Exception:  # noqa: BLE001 - never leak exception text; it may carry credentials
            self.errors.append(PartialReadError(resource=resource, reason="error", optional=optional))
        return None

    async def collect(self, ref: WorkloadRef) -> Evidence:
        lim = self._limits
        is_job = ref.kind in ("Job", "CronJob")
        # Fetch up to a ceiling, then select: truncating at the source could drop the failing pod.
        ws, pods, ns_phase, jobs = await asyncio.gather(
            self.call("workload_status", lambda: self._src.get_workload_status(ref)),
            self.call("pods", lambda: self._src.list_pods(ref, lim.max_pods_fetched + 1)),
            self.call("namespace", lambda: self._src.get_namespace_phase(ref.namespace),
                      optional=True),
            self.call("jobs", lambda: self._src.list_jobs(ref)) if is_job else _none(),
        )
        if ws is not None:
            self._workload = ws
            self._available.add("workload")
        if ns_phase is not None:
            self._ns_phase = ns_phase
            self._available.add("namespace")
        if is_job:
            if jobs is not None:
                self._jobs = list(jobs)
                self._available.add("jobs")
        else:
            self._available.add("jobs")  # not applicable to this kind: nothing to read
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

        if pods is not None:
            await self._collect_related(ref)
        return self.snapshot()

    async def _collect_related(self, ref: WorkloadRef) -> None:
        pods = self._pods
        node_names = sorted({p.node_name for p in pods if p.node_name})
        claims = sorted({c for p in pods for c in p.pvc_claims})
        no_nodes: list[NodeEvidence] = []
        no_pvcs: list[PvcEvidence] = []
        nodes_aw: Awaitable[list[NodeEvidence] | None] = (
            self.call("nodes", lambda: self._src.get_nodes(node_names), optional=True) if node_names
            else _value(no_nodes))
        pvcs_aw: Awaitable[list[PvcEvidence] | None] = (
            self.call("pvcs", lambda: self._src.list_pvcs(ref, claims)) if claims
            else _value(no_pvcs))
        nodes, pvcs, services = await asyncio.gather(
            nodes_aw, pvcs_aw,
            self.call("services", lambda: self._src.list_services(ref, pods)),
        )
        if nodes is not None:
            self._nodes = list(nodes)
            self._available.add("nodes")
        if pvcs is not None:
            self._pvcs = list(pvcs)
            self._available.add("pvcs")
        if services is not None:
            self._services = list(services)
            self._available.add("services")
        if self._collect_logs:
            await self._read_logs(ref)

    async def _read_logs(self, ref: WorkloadRef) -> None:
        lim = self._limits
        targets = log_targets(self._pods, lim.max_log_containers)

        async def one(pod: str, container: str, previous: bool) -> ContainerLog | None:
            return await self.call(
                f"logs:{pod}/{container}",
                lambda: self._src.get_logs(ref, pod, container, previous,
                                           lim.max_log_lines, lim.max_log_bytes),
                ignore_not_found=True,
            )

        results = await asyncio.gather(*(one(*t) for t in targets))
        self._logs = [r for r in results if r is not None and r.lines]
        failed = len([e for e in self.errors if e.resource.startswith("logs:")])
        if not targets or failed < len(targets):
            self._available.add("logs")

    def snapshot(self) -> Evidence:
        return Evidence(
            pods=tuple(self._pods), events=tuple(self._events), nodes=tuple(self._nodes),
            pvcs=tuple(self._pvcs), services=tuple(self._services), jobs=tuple(self._jobs),
            logs=tuple(self._logs), namespace_phase=self._ns_phase, workload=self._workload,
            available=frozenset(self._available), partial_errors=tuple(self.errors),
            truncated=self._truncated,
        )


async def _none() -> None:
    return None


async def _value(v: T) -> T | None:
    return v
