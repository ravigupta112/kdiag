"""Ranking and report assembly. Deterministic: same input, same report."""
from __future__ import annotations

from datetime import datetime

from .mask import mask_text
from .models import (
    DiagnosisInput,
    DiagnosisReport,
    Evidence,
    Finding,
    SkippedRule,
    Status,
    WorkloadStatus,
)

_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def rank_key(f: Finding) -> tuple[bool, int, int, int, str, str]:
    """definitive first, then confidence, then earliest in the causal chain, then priority."""
    return (not f.definitive, _CONF_RANK[f.confidence], f.causal_order, -f.priority,
            f.rule_id, f.sub_cause)


def _mask_finding(f: Finding) -> Finding:
    """Defence in depth: report strings are masked again."""
    return f.model_copy(update={
        "summary": mask_text(f.summary) or "",
        "next_action": mask_text(f.next_action) or "",
        "evidence_refs": tuple(mask_text(r) or "" for r in f.evidence_refs),
        "details": {k: mask_text(v) or "" for k, v in f.details.items()},
    })


def _rollout_complete(ws: WorkloadStatus) -> bool:
    if ws.observed_generation < ws.generation:
        return False
    if not (ws.updated_replicas == ws.ready_replicas == ws.available_replicas == ws.replicas):
        return False
    for c in ws.conditions:
        if c.type == "ReplicaFailure" and c.status == "True":
            return False
        if c.type == "Progressing" and c.reason == "ProgressDeadlineExceeded":
            return False
    return True


def _pods_healthy(ev: Evidence) -> bool:
    if not ev.pods:
        return False
    for p in ev.pods:
        if p.phase == "Succeeded":
            continue
        if p.phase != "Running" or not all(c.ready for c in p.containers if not c.is_init):
            return False
    return True


def _healthy(ev: Evidence) -> bool:
    """Healthy pods are not enough: old-revision pods can look fine while the rollout is stuck."""
    if ev.truncated:  # we did not see everything, so we cannot say everything is fine
        return False
    return _pods_healthy(ev) and ev.workload is not None and _rollout_complete(ev.workload)


def _notes(ev: Evidence, primary: Finding | None) -> tuple[str, ...]:
    notes: list[str] = []
    if ev.truncated:
        notes.append("Evidence was truncated to fit limits: some pods or events were not inspected")
    ws = ev.workload
    if ws is not None and not _rollout_complete(ws):
        n = ws.replicas
        notes.append(f"Rollout incomplete: {ws.updated_replicas}/{n} updated, "
                     f"{ws.ready_replicas}/{n} ready, {ws.available_replicas}/{n} available")
        for c in ws.conditions:
            if c.type == "ReplicaFailure" and c.status == "True":
                notes.append("ReplicaFailure: " + (c.message or c.reason or "no message"))
            if c.type == "Progressing" and c.reason == "ProgressDeadlineExceeded":
                notes.append("Progress deadline exceeded")
    elif ws is None and primary is None and _pods_healthy(ev):
        notes.append("Pods look healthy, but rollout status was not available, "
                     "so the deployment cannot be confirmed healthy")
    return tuple(mask_text(n) or "" for n in notes)


def build_report(
    *,
    inp: DiagnosisInput,
    findings: list[Finding],
    ev: Evidence,
    skipped: list[SkippedRule],
    rule_errors: list[str],
    now: datetime,
    status_override: Status | None = None,
    candidates: tuple[str, ...] = (),
) -> DiagnosisReport:
    ranked = sorted((_mask_finding(f) for f in findings), key=rank_key)
    primary = next((f for f in ranked if not f.outcome_only), None)
    supporting = tuple(f for f in ranked if f is not primary)

    status: Status
    if status_override:
        status = status_override
    elif any(not e.optional for e in ev.partial_errors):
        status = "partial"  # a primary finding may still be present; the gaps are listed
    elif primary:
        status = "diagnosed"
    elif _healthy(ev):
        status = "no_issue_detected"
    else:
        status = "unknown"

    report = DiagnosisReport(
        status=status, mode=inp.mode, target=inp.target, primary=primary, supporting=supporting,
        partial_errors=ev.partial_errors, skipped_rules=tuple(skipped),
        rule_errors=tuple(rule_errors), notes=_notes(ev, primary), candidates=candidates,
        stale_events_suppressed=ev.stale_events_suppressed, truncated=ev.truncated, collected_at=now,
    )
    limit = inp.limits.max_report_bytes
    while len(report.model_dump_json()) > limit and report.supporting:
        report = report.model_copy(update={"supporting": report.supporting[:-1], "truncated": True})
    if len(report.model_dump_json()) > limit:
        report = report.model_copy(update={"truncated": True})  # even the primary alone is over budget
    return report
