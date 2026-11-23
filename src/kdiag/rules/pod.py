"""POD-006 eviction."""
from __future__ import annotations

from collections.abc import Iterable

from ..models import Evidence
from .table import TableRule, sub


class EvictionRule(TableRule):
    id, priority, causal_order = "POD-006", 72, 8
    table = (
        sub("disk", r"ephemeral-storage|disk|DiskPressure", "high",
            "The pod was evicted because the node ran low on disk or ephemeral storage",
            "Reduce ephemeral-storage use (logs, emptyDir, image layers) or add node disk"),
        sub("memory", r"memory", "high",
            "The pod was evicted because the node ran low on memory",
            "Set memory requests/limits correctly and check node memory pressure"),
        sub("pid", r"\bpids?\b", "high",
            "The pod was evicted because the node ran out of process IDs",
            "Check for process leaks and node PID limits"),
        sub("other", r".", "medium", "The pod was evicted by the kubelet",
            "Read the pod status message for the eviction reason"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        for p in ev.pods:
            if p.reason == "Evicted" or p.phase == "Failed" and p.reason == "Evicted":
                yield f"pod/{p.name}", p.message or "evicted"
