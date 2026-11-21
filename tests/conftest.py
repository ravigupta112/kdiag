from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from kdiag import (
    Condition,
    ContainerEvidence,
    DiagnosisInput,
    EventEvidence,
    PodEvidence,
    Target,
    WorkloadRef,
)

NOW = datetime(2026, 11, 21, 10, 15, tzinfo=UTC)
REF = WorkloadRef(kind="Deployment", name="shop-web", namespace="shop-prod")
TARGET = Target(kind="Deployment", name="shop-web", namespace="shop-prod")


def run(coro):
    return asyncio.run(coro)


def pod(name="shop-web-1", phase="Running", containers=(), conditions=(), ns="shop-prod"):
    return PodEvidence(name=name, namespace=ns, phase=phase,
                       containers=tuple(containers), conditions=tuple(conditions))


def ctr(name="web", **kw):
    return ContainerEvidence(name=name, **kw)


def unschedulable(msg: str, name="shop-web-2"):
    return pod(name, "Pending", conditions=[
        Condition(type="PodScheduled", status="False", reason="Unschedulable", message=msg)])


def pull_pod(msg: str, reason="ImagePullBackOff", name="shop-web-1"):
    return pod(name, "Pending", containers=[
        ctr(waiting_reason=reason, waiting_message=msg)])


def ev_input(**kw):
    return DiagnosisInput(mode="evidence", **kw)


def cluster_input(**kw):
    return DiagnosisInput(mode="cluster", target=TARGET, **kw)


def event(reason="Failed", message="", pod_name="shop-web-1", ts=NOW, type_="Warning"):
    return EventEvidence(object_kind="Pod", object_name=pod_name, type=type_, reason=reason,
                         message=message, timestamp=ts)
