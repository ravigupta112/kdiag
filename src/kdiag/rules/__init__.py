from __future__ import annotations

from .admission import AdmissionRule
from .applogs import NetworkLogRule, NodeLogRule, PythonLogRule
from .base import Registry, Rule
from .config import ContainerStartRule, MissingConfigRule
from .crashloop import CrashLoopRule
from .image import ImageRule
from .network import CniRule, ServiceEndpointsRule
from .node import NamespaceTerminatingRule, NodeConditionRule
from .oom import OOMKilledRule
from .pod import EvictionRule
from .probe import ProbeRule
from .sched import UnschedulableRule
from .storage import MountFailureRule, PendingPvcRule
from .workload import JobFailureRule, ProgressDeadlineRule, ReplicaFailureRule

_ALL: tuple[type, ...] = (
    ImageRule, OOMKilledRule, CrashLoopRule, UnschedulableRule, MissingConfigRule,
    ContainerStartRule, EvictionRule, NodeConditionRule, NamespaceTerminatingRule, AdmissionRule,
    ProbeRule, PendingPvcRule, MountFailureRule, ServiceEndpointsRule, CniRule, ReplicaFailureRule,
    ProgressDeadlineRule, JobFailureRule, PythonLogRule, NodeLogRule, NetworkLogRule,
)


def default_registry() -> Registry:
    reg = Registry()
    for cls in _ALL:
        reg.register(cls())
    return reg


__all__ = ["Registry", "Rule", "default_registry"]
