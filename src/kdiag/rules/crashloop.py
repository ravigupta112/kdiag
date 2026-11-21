"""POD-004: CrashLoopBackOff. Reports the loop, never invents why the app crashed."""
from __future__ import annotations

from ..models import Evidence, Finding


class CrashLoopRule:
    id = "POD-004"
    priority = 60
    requires = frozenset({"pods"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        out: list[Finding] = []
        for pod in ev.pods:
            for c in pod.containers:
                if c.waiting_reason != "CrashLoopBackOff":
                    continue
                if "OOMKilled" in (c.terminated_reason, c.last_terminated_reason):
                    continue  # POD-005 already explains this loop
                code = c.last_exit_code if c.last_exit_code is not None else c.terminated_exit_code
                sub = f"exit_{code}" if code is not None else "exit_unknown"
                out.append(Finding(
                    rule_id=self.id, sub_cause=sub, confidence="high",
                    summary=(f"Container {c.name} keeps crashing"
                             + (f" (last exit code {code})" if code is not None else "")
                             + "; the application error itself is not visible in cluster state"),
                    next_action="Read the previous container logs to find the application error",
                    evidence_refs=(f"pod/{pod.name}/container/{c.name}",),
                    causal_order=40, priority=self.priority,
                    details={"restarts": str(c.restart_count)},
                ))
        return sorted(out, key=lambda f: f.evidence_refs)
