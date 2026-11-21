"""Mask and normalise evidence before any rule sees it."""
from __future__ import annotations

from datetime import UTC, datetime

from .mask import mask_text
from .models import Condition, ContainerEvidence, EventEvidence, PodEvidence


def _utc(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


def _pod(p: PodEvidence) -> PodEvidence:
    return p.model_copy(update={
        "conditions": tuple(
            Condition(type=c.type, status=c.status, reason=c.reason, message=mask_text(c.message))
            for c in p.conditions),
        "containers": tuple(
            c.model_copy(update={"waiting_message": mask_text(c.waiting_message)})
            for c in p.containers),
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
    start = _utc(window_start)
    kept: list[EventEvidence] = []
    stale = 0
    for e in events:
        ts = _utc(e.timestamp)
        if ts is not None and start is not None and ts < start:
            stale += 1
            continue
        kept.append(e.model_copy(update={
            "timestamp": ts, "time_unknown": ts is None,
            "message": mask_text(e.message) or "",
        }))
    return tuple(_pod(p) for p in pods), tuple(kept), stale


__all__ = ["ContainerEvidence", "normalize"]
