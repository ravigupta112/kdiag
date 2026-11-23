"""Mask and normalise evidence before any rule sees it."""
from __future__ import annotations

from datetime import datetime

from .mask import mask_text
from .models import (
    Condition,
    ContainerLog,
    EventEvidence,
    JobEvidence,
    NodeEvidence,
    PodEvidence,
    WorkloadStatus,
)
from .timeutil import to_utc

LOG_LINE_MAX = 500


def _cond(c: Condition) -> Condition:
    return Condition(type=c.type, status=c.status, reason=c.reason, message=mask_text(c.message))


def _pod(p: PodEvidence) -> PodEvidence:
    return p.model_copy(update={
        "reason": mask_text(p.reason, 253),
        "message": mask_text(p.message),
        "conditions": tuple(_cond(c) for c in p.conditions),
        "containers": tuple(
            c.model_copy(update={
                "waiting_message": mask_text(c.waiting_message),
                "terminated_message": mask_text(c.terminated_message),
                "last_terminated_message": mask_text(c.last_terminated_message),
            }) for c in p.containers),
    })


def normalize(
    pods: tuple[PodEvidence, ...],
    events: tuple[EventEvidence, ...],
    window_start: datetime | None,
) -> tuple[tuple[PodEvidence, ...], tuple[EventEvidence, ...], int]:
    """Returns (pods, events, stale_events_suppressed).

    Events with a missing timestamp are kept but flagged time_unknown. Events older
    than window_start are suppressed and counted. Naive timestamps are treated as UTC.
    """
    start = to_utc(window_start)
    kept: list[EventEvidence] = []
    stale = 0
    for e in events:
        ts = to_utc(e.timestamp)
        if ts is not None and start is not None and ts < start:
            stale += 1
            continue
        kept.append(e.model_copy(update={
            "timestamp": ts, "time_unknown": ts is None,
            "message": mask_text(e.message) or "",
        }))
    return tuple(_pod(p) for p in pods), tuple(kept), stale


def normalize_workload(ws: WorkloadStatus | None) -> WorkloadStatus | None:
    if ws is None:
        return None
    return ws.model_copy(update={"conditions": tuple(_cond(c) for c in ws.conditions)})


def normalize_nodes(nodes: tuple[NodeEvidence, ...]) -> tuple[NodeEvidence, ...]:
    return tuple(n.model_copy(update={"conditions": tuple(_cond(c) for c in n.conditions)})
                 for n in nodes)


def normalize_jobs(jobs: tuple[JobEvidence, ...]) -> tuple[JobEvidence, ...]:
    return tuple(j.model_copy(update={"conditions": tuple(_cond(c) for c in j.conditions)})
                 for j in jobs)


def normalize_logs(logs: tuple[ContainerLog, ...]) -> tuple[ContainerLog, ...]:
    return tuple(lg.model_copy(update={
        "lines": tuple(mask_text(line, LOG_LINE_MAX) or "" for line in lg.lines)}) for lg in logs)


__all__ = [
    "normalize", "normalize_jobs", "normalize_logs", "normalize_nodes", "normalize_workload",
]
