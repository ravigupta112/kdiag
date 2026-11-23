"""WL-001/002 controller outcomes; WL-003 Job failures."""
from __future__ import annotations

from ..mask import mask_text
from ..models import Evidence, Finding


class ReplicaFailureRule:
    id = "WL-001"
    priority = 40
    requires = frozenset({"workload"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        assert ev.workload is not None
        out: list[Finding] = []
        for c in ev.workload.conditions:
            if c.type == "ReplicaFailure" and c.status == "True":
                out.append(Finding(
                    rule_id=self.id, sub_cause="replica_failure", confidence="high",
                    summary="The controller could not create pods (the reason is in the related findings)",
                    next_action="Look at admission, quota and scheduling findings for the cause",
                    evidence_refs=("workload/ReplicaFailure",), causal_order=90, priority=self.priority,
                    outcome_only=True, details={"message": mask_text(c.message, 200) or ""},
                ))
        return out


class ProgressDeadlineRule:
    id = "WL-002"
    priority = 40
    requires = frozenset({"workload"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        assert ev.workload is not None
        for c in ev.workload.conditions:
            if c.type == "Progressing" and c.reason == "ProgressDeadlineExceeded":
                return [Finding(
                    rule_id=self.id, sub_cause="progress_deadline", confidence="high",
                    summary="The rollout exceeded its progress deadline (an outcome, not a root cause)",
                    next_action="Look at the pod-level findings to see what stopped the rollout",
                    evidence_refs=("workload/Progressing",), causal_order=95, priority=self.priority,
                    outcome_only=True,
                )]
        return []


class JobFailureRule:
    id = "WL-003"
    priority = 60
    requires = frozenset({"jobs"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        out: list[Finding] = []
        for job in ev.jobs:
            for c in job.conditions:
                if c.type != "Failed" or c.status != "True":
                    continue
                if c.reason == "DeadlineExceeded":
                    out.append(Finding(
                        rule_id=self.id, sub_cause="deadline_exceeded", confidence="high",
                        summary=f"Job {job.name} ran longer than its activeDeadlineSeconds",
                        next_action="Raise activeDeadlineSeconds or make the job faster",
                        evidence_refs=(f"job/{job.name}",), causal_order=70, priority=self.priority,
                    ))
                elif c.reason == "BackoffLimitExceeded":
                    out.append(Finding(
                        rule_id=self.id, sub_cause="backoff_limit", confidence="high",
                        summary=f"Job {job.name} failed too many times (backoffLimit reached)",
                        next_action="Read the failed pods' previous logs and events for the underlying error",
                        evidence_refs=(f"job/{job.name}",), causal_order=75, priority=self.priority,
                        outcome_only=True,
                    ))
        return out
