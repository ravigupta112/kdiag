"""Kubernetes SDK objects -> kdiag evidence. Pure functions, duck-typed, no SDK import.

Never read: container env, volume secret data, Secret objects. Only status and metadata are used.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import (
    Condition,
    ContainerEvidence,
    EventEvidence,
    JobEvidence,
    MatchedBy,
    NodeEvidence,
    PodEvidence,
    PvcEvidence,
    WorkloadStatus,
)

_MAX_LABELS = 64


def _conditions(items: Any) -> tuple[Condition, ...]:
    out = []
    for c in items or []:
        out.append(Condition(type=str(c.type)[:253], status=str(c.status)[:253],
                             reason=(str(c.reason)[:253] if getattr(c, "reason", None) else None),
                             message=getattr(c, "message", None)))
    return tuple(out[:50])


def _labels(d: Any) -> dict[str, str]:
    if not d:
        return {}
    return {str(k)[:253]: str(v)[:253] for k, v in list(d.items())[:_MAX_LABELS]}


def _container(status: Any, limits: dict[str, str], is_init: bool) -> ContainerEvidence:
    st = getattr(status, "state", None)
    last = getattr(status, "last_state", None)
    waiting = getattr(st, "waiting", None)
    term = getattr(st, "terminated", None)
    last_term = getattr(last, "terminated", None)
    return ContainerEvidence(
        name=status.name, is_init=is_init, ready=bool(getattr(status, "ready", False)),
        restart_count=int(getattr(status, "restart_count", 0) or 0),
        waiting_reason=getattr(waiting, "reason", None), waiting_message=getattr(waiting, "message", None),
        terminated_reason=getattr(term, "reason", None), terminated_message=getattr(term, "message", None),
        terminated_exit_code=getattr(term, "exit_code", None),
        last_terminated_reason=getattr(last_term, "reason", None),
        last_terminated_message=getattr(last_term, "message", None),
        last_exit_code=getattr(last_term, "exit_code", None),
        memory_limit=limits.get(status.name),
    )


def pod_from_v1(pod: Any, matched_by: MatchedBy = "owner") -> PodEvidence:
    spec, status, meta = pod.spec, pod.status, pod.metadata
    limits: dict[str, str] = {}
    for c in list(getattr(spec, "containers", None) or []) + list(getattr(spec, "init_containers", None) or []):
        lim = getattr(getattr(c, "resources", None), "limits", None) or {}
        if "memory" in lim:
            limits[c.name] = str(lim["memory"])
    containers = [_container(s, limits, False) for s in getattr(status, "container_statuses", None) or []]
    containers += [_container(s, limits, True) for s in getattr(status, "init_container_statuses", None) or []]
    claims = tuple(sorted({
        v.persistent_volume_claim.claim_name for v in getattr(spec, "volumes", None) or []
        if getattr(v, "persistent_volume_claim", None)
    }))[:50]
    return PodEvidence(
        name=meta.name, namespace=meta.namespace, phase=getattr(status, "phase", None) or "Unknown",
        reason=getattr(status, "reason", None), message=getattr(status, "message", None),
        node_name=getattr(spec, "node_name", None), labels=_labels(getattr(meta, "labels", None)),
        pvc_claims=claims, matched_by=matched_by,
        conditions=_conditions(getattr(status, "conditions", None)), containers=tuple(containers[:50]),
    )


def event_time(ev: Any) -> datetime | None:
    series = getattr(ev, "series", None)
    for ts in (getattr(series, "last_observed_time", None), getattr(ev, "last_timestamp", None),
               getattr(ev, "event_time", None), getattr(ev, "first_timestamp", None)):
        if ts is not None:
            return ts  # type: ignore[no-any-return]
    return None  # unknown stays unknown: never substitute "now"


def event_from_v1(ev: Any) -> EventEvidence:
    obj = ev.involved_object
    return EventEvidence(
        object_kind=obj.kind or "", object_name=obj.name or "", type=ev.type or "Normal",
        reason=ev.reason or "", message=ev.message or "", timestamp=event_time(ev),
        count=int(getattr(ev, "count", 1) or 1),
    )


def node_from_v1(node: Any) -> NodeEvidence:
    return NodeEvidence(name=node.metadata.name, conditions=_conditions(node.status.conditions))


def pvc_from_v1(pvc: Any) -> PvcEvidence:
    return PvcEvidence(
        name=pvc.metadata.name, namespace=pvc.metadata.namespace,
        phase=getattr(pvc.status, "phase", None) or "Unknown",
        storage_class=getattr(pvc.spec, "storage_class_name", None),
    )


def job_from_v1(job: Any) -> JobEvidence:
    st = job.status
    return JobEvidence(
        name=job.metadata.name, namespace=job.metadata.namespace,
        active=int(getattr(st, "active", 0) or 0), failed=int(getattr(st, "failed", 0) or 0),
        succeeded=int(getattr(st, "succeeded", 0) or 0),
        conditions=_conditions(getattr(st, "conditions", None)),
    )


def workload_status_from_v1(obj: Any) -> WorkloadStatus:
    st = obj.status
    ready = int(getattr(st, "ready_replicas", 0) or 0)
    avail = getattr(st, "available_replicas", None)
    return WorkloadStatus(
        generation=int(getattr(obj.metadata, "generation", 0) or 0),
        observed_generation=int(getattr(st, "observed_generation", 0) or 0),
        replicas=int(getattr(obj.spec, "replicas", 1) if getattr(obj.spec, "replicas", None) is not None else 1),
        updated_replicas=int(getattr(st, "updated_replicas", 0) or 0),
        ready_replicas=ready,
        available_replicas=int(avail) if avail is not None else ready,  # StatefulSet: older clusters omit it
        conditions=_conditions(getattr(st, "conditions", None)),
    )


def endpoint_counts(slices: list[Any]) -> tuple[int, int]:
    """(ready, not_ready). Per the EndpointSlice API, a nil `ready` condition means ready."""
    ready = not_ready = 0
    for sl in slices:
        for ep in getattr(sl, "endpoints", None) or []:
            cond = getattr(ep, "conditions", None)
            if getattr(cond, "ready", None) is False:
                not_ready += 1
            else:
                ready += 1
    return ready, not_ready
