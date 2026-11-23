"""NODE-001 node conditions; NS-001 namespace terminating."""
from __future__ import annotations

from ..models import Evidence, Finding

_BAD_TRUE = {
    "DiskPressure": ("disk_pressure", "The node is under disk pressure",
                     "Free disk on the node or move the workload to another node"),
    "MemoryPressure": ("memory_pressure", "The node is under memory pressure",
                       "Reduce memory use on the node or add capacity"),
    "PIDPressure": ("pid_pressure", "The node is running out of process IDs",
                    "Check for process leaks on the node"),
    "NetworkUnavailable": ("network_unavailable", "The node network is not configured",
                           "Check the CNI plugin on the node"),
}


class NodeConditionRule:
    id = "NODE-001"
    priority = 85
    requires = frozenset({"nodes"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        groups: dict[str, tuple[str, str, str, list[str]]] = {}
        for node in ev.nodes:
            for c in node.conditions:
                if c.type == "Ready" and c.status != "True":
                    key = "not_ready_unknown" if c.status == "Unknown" else "not_ready"
                    text = ("The node stopped reporting status (kubelet or node is down)"
                            if c.status == "Unknown" else "The node is NotReady")
                    nxt = "Check the node, kubelet and network; pods on it may be rescheduled"
                    groups.setdefault(key, (key, text, nxt, []))[3].append(f"node/{node.name}")
                elif c.type in _BAD_TRUE and c.status == "True":
                    key, text, nxt = _BAD_TRUE[c.type]
                    groups.setdefault(key, (key, text, nxt, []))[3].append(f"node/{node.name}")
        return [
            Finding(rule_id=self.id, sub_cause=k, confidence="high", summary=text, next_action=nxt,
                    evidence_refs=tuple(sorted(refs)), causal_order=5, priority=self.priority)
            for k, (_, text, nxt, refs) in sorted(groups.items())
        ]


class NamespaceTerminatingRule:
    id = "NS-001"
    priority = 95
    requires = frozenset({"namespace"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        if ev.namespace_phase != "Terminating":
            return []
        return [Finding(
            rule_id=self.id, sub_cause="terminating", confidence="high",
            summary="The namespace is terminating, so new resources cannot be created in it",
            next_action="Wait for namespace deletion to finish, or deploy into another namespace",
            evidence_refs=("namespace",), causal_order=1, priority=self.priority,
        )]
