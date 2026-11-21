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
        "details": {
            (mask_text(k) or "")[:2000]: mask_text(v) or ""
            for k, v in f.details.items()
        },
    })


def _healthy(ev: Evidence) -> bool:
    if not ev.pods:
        return False
    for p in ev.pods:
        if p.phase == "Succeeded":
            continue
        if p.phase != "Running":
            return False
        if not all(c.ready for c in p.containers if not c.is_init):
            return False
    return True


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
    elif ev.partial_errors:
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
        rule_errors=tuple(rule_errors), candidates=candidates,
        stale_events_suppressed=ev.stale_events_suppressed, truncated=ev.truncated, collected_at=now,
    )
    limit = inp.limits.max_report_bytes
    while len(report.model_dump_json()) > limit and report.supporting:
        report = report.model_copy(update={"supporting": report.supporting[:-1], "truncated": True})
    if len(report.model_dump_json()) > limit and report.primary:
        compact_primary = report.primary.model_copy(update={
            "summary": mask_text(report.primary.summary, max_len=500) or "",
            "next_action": mask_text(report.primary.next_action, max_len=500) or "",
            "evidence_refs": report.primary.evidence_refs[:10],
            "details": {},
        })
        report = report.model_copy(update={
            "primary": compact_primary,
            "supporting": (),
            "truncated": True,
        })
    if len(report.model_dump_json()) > limit:
        report = report.model_copy(update={
            "candidates": (),
            "skipped_rules": (),
            "rule_errors": (),
            "truncated": True,
        })
    return report
