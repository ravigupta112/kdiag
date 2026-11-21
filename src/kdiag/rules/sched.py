"""SCHED-001: pod unschedulable; sub-cause chosen by node counts in the scheduler message."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Evidence, Finding

_SEGMENT = re.compile(r"(\d+)\s+([^,.]+)")
_TABLE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("taint", re.compile(r"(?i)taint")),
    ("insufficient", re.compile(r"(?i)insufficient")),
    ("affinity", re.compile(r"(?i)node affinity|node selector")),
    ("topology", re.compile(r"(?i)topology spread")),
    ("anti_affinity", re.compile(r"(?i)pod anti-affinity|pod affinity")),
    ("unbound_pvc", re.compile(r"(?i)unbound immediate persistentvolumeclaims|persistentvolumeclaim")),
)
_SUMMARY = {
    "taint": "No node can run the pod: nodes have taints the pod does not tolerate",
    "insufficient": "No node has enough free resources for the pod's requests",
    "affinity": "No node matches the pod's node affinity or node selector",
    "topology": "The pod's topology spread constraints cannot be satisfied",
    "anti_affinity": "Pod affinity or anti-affinity rules leave no eligible node",
    "unbound_pvc": "The pod references a PersistentVolumeClaim that is not bound",
    "unclassified": "The scheduler reports the pod as unschedulable for an unrecognised reason",
}
_NEXT = {
    "taint": "Add a matching toleration or schedule onto a node pool without the taint",
    "insufficient": "Lower the resource requests, add capacity, or free resources on nodes",
    "affinity": "Fix nodeSelector/affinity labels or label a suitable node",
    "topology": "Relax maxSkew/whenUnsatisfiable or add nodes in the missing topology domains",
    "anti_affinity": "Relax the affinity rules or add nodes",
    "unbound_pvc": "Check the PVC status and its StorageClass",
    "unclassified": "Read the FailedScheduling message on the pod",
}


@dataclass
class _Group:
    detail: str
    refs: list[str] = field(default_factory=list)


class UnschedulableRule:
    id = "SCHED-001"
    priority = 80
    requires = frozenset({"pods"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        groups: dict[str, _Group] = {}
        for pod in ev.pods:
            for cond in pod.conditions:
                if not (cond.type == "PodScheduled" and cond.status == "False"
                        and cond.reason == "Unschedulable"):
                    continue
                sub, detail = self._classify(cond.message or "")
                groups.setdefault(sub, _Group(detail=detail)).refs.append(f"pod/{pod.name}")
        return [
            Finding(
                rule_id=self.id, sub_cause=sub,
                confidence="medium" if sub == "unclassified" else "high",
                summary=_SUMMARY[sub], next_action=_NEXT[sub],
                evidence_refs=tuple(sorted(g.refs)), causal_order=10, priority=self.priority,
                details={"scheduler_breakdown": g.detail} if g.detail else {},
            )
            for sub, g in sorted(groups.items())
        ]

    @staticmethod
    def _classify(message: str) -> tuple[str, str]:
        _, _, tail = message.partition(": ")
        counts: dict[str, int] = {}
        parts: list[str] = []
        for n, text in _SEGMENT.findall(tail):
            for sub, rx in _TABLE:
                if rx.search(text):
                    counts[sub] = counts.get(sub, 0) + int(n)
                    parts.append(f"{sub}={n}")
                    break
        if not counts:  # e.g. "pod has unbound immediate PersistentVolumeClaims" carries no count
            for sub, rx in _TABLE:
                if rx.search(tail):
                    return sub, ""
            return "unclassified", ""
        order = [s for s, _ in _TABLE]
        best = min(counts, key=lambda s: (-counts[s], order.index(s)))
        return best, "; ".join(parts)
