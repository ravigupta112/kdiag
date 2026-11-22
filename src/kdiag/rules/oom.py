"""POD-005: container killed for exceeding its memory limit."""
from __future__ import annotations

from ..models import Evidence, Finding


class OOMKilledRule:
    id = "POD-005"
    priority = 75
    requires = frozenset({"pods"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        out: list[Finding] = []
        for pod in ev.pods:
            for c in pod.containers:
                if "OOMKilled" not in (c.terminated_reason, c.last_terminated_reason):
                    continue
                if c.ready and c.waiting_reason is None:
                    out.append(Finding(
                        rule_id=self.id, sub_cause="previous_oom", confidence="low",
                        summary=f"Container {c.name} was killed for memory earlier but is running now",
                        next_action="Check memory use and limits if restarts keep happening",
                        evidence_refs=(f"pod/{pod.name}/container/{c.name}",),
                        causal_order=60, priority=self.priority,
                        details={"restarts": str(c.restart_count)},
                    ))
                    continue
                limit = c.memory_limit
                where = f" (limit {limit})" if limit else ""
                details = {"restarts": str(c.restart_count)}
                if limit:
                    details["memory_limit"] = limit
                out.append(Finding(
                    rule_id=self.id, sub_cause="memory_limit", confidence="high",
                    summary=f"Container {c.name} was killed for exceeding its memory limit{where}",
                    next_action="Raise the memory limit or investigate the container's memory use",
                    evidence_refs=(f"pod/{pod.name}/container/{c.name}",),
                    causal_order=30, priority=self.priority, details=details,
                ))
        return sorted(out, key=lambda f: f.evidence_refs)
