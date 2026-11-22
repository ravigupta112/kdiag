"""diagnose(): the single public entry point. Deterministic; never calls an LLM."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from .collect import Collector
from .helm import helm_finding, parse_helm
from .models import (
    DiagnosisInput,
    DiagnosisReport,
    Evidence,
    Finding,
    PartialReadError,
    SkippedRule,
    Status,
    WorkloadStatus,
)
from .normalize import normalize, normalize_workload
from .report import build_report
from .rules import Registry, default_registry
from .sources import EvidenceSource


async def diagnose(
    inp: DiagnosisInput,
    src: EvidenceSource | None = None,
    *,
    registry: Registry | None = None,
    now: datetime | None = None,
) -> DiagnosisReport:
    now = now or datetime.now(UTC)
    reg = registry or default_registry()

    helm_text = "\n".join(t for t in (inp.helm_output, inp.job_log) if t)
    helm = helm_finding(parse_helm(helm_text))

    pods = inp.pods
    events = inp.events
    workload: WorkloadStatus | None = inp.workload_status
    available: set[str] = set()
    if inp.pods:
        available.add("pods")
    if inp.events:
        available.add("events")
    if workload is not None:
        available.add("workload")
    errors: list[PartialReadError] = []
    truncated = False
    candidates: tuple[str, ...] = ()
    override: Status | None = None

    if inp.mode != "evidence":
        if src is None or inp.target is None:
            raise ValueError("cluster and hybrid mode need an EvidenceSource and a target")
        target = inp.target
        collector = Collector(src, inp.limits)
        try:
            async with asyncio.timeout(inp.limits.overall_timeout_s):
                refs = await collector.call("workload", lambda: src.find_workloads(target))
                if refs is None:
                    reasons = {e.reason for e in collector.errors}
                    override = ("cluster_unreachable" if "unreachable" in reasons
                                else "target_not_found" if "not_found" in reasons else None)
                elif not refs:
                    override = "target_not_found"
                elif len(refs) > 1:
                    override = "ambiguous_target"
                    candidates = tuple(sorted(f"{r.namespace}/{r.kind}/{r.name}" for r in refs))
                else:
                    await collector.collect(refs[0])
        except TimeoutError:
            collector.errors.append(
                PartialReadError(resource="overall", reason="timeout", retryable=True))
        got = collector.snapshot()  # whatever was gathered, even if the deadline cut collection short
        by_name = {p.name: p for p in pods}
        by_name.update({p.name: p for p in got.pods})
        pods = tuple(by_name.values())
        events = events + got.events
        workload = got.workload or workload
        available |= set(got.available)
        truncated = got.truncated
        errors = list(collector.errors)

    pods, events, stale = normalize(pods, events, inp.window_start)
    ev = Evidence(
        pods=pods, events=events, workload=normalize_workload(workload),
        available=frozenset(available), partial_errors=tuple(errors), truncated=truncated,
        stale_events_suppressed=stale,
    )

    findings: list[Finding] = []
    skipped: list[SkippedRule] = []
    rule_errors: list[str] = []
    # An unreachable cluster still lets rules run over evidence the caller supplied.
    if override in (None, "cluster_unreachable"):
        for rule in reg.all():
            missing = tuple(sorted(rule.requires - ev.available))
            if missing:
                skipped.append(SkippedRule(rule_id=rule.id, missing=missing))
                continue
            try:
                findings.extend(rule.evaluate(ev))
            except Exception as exc:  # noqa: BLE001 - one bad rule must not hide the others
                rule_errors.append(f"{rule.id}: {type(exc).__name__}")
    if helm:
        findings.append(helm)

    return build_report(
        inp=inp, findings=findings, ev=ev, skipped=skipped, rule_errors=rule_errors, now=now,
        status_override=override, candidates=candidates,
    )
