"""diagnose(): the single public entry point. Deterministic; never calls an LLM."""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

from .collect import Collector
from .helm import helm_finding, parse_helm
from .mask import track_masking
from .models import (
    DiagnosisInput,
    DiagnosisReport,
    Evidence,
    Finding,
    PartialReadError,
    SkippedRule,
    Status,
)
from .normalize import (
    normalize,
    normalize_jobs,
    normalize_logs,
    normalize_nodes,
    normalize_workload,
)
from .observability import NULL_METRICS, Metrics
from .report import build_report
from .rules import Registry, default_registry
from .sources import EvidenceSource


def _supplied_kinds(inp: DiagnosisInput) -> set[str]:
    pairs = {"pods": inp.pods, "events": inp.events, "nodes": inp.nodes, "pvcs": inp.pvcs,
             "services": inp.services, "jobs": inp.jobs, "logs": inp.logs}
    kinds = {k for k, v in pairs.items() if v}
    if inp.workload_status is not None:
        kinds.add("workload")
    if inp.namespace_phase is not None:
        kinds.add("namespace")
    return kinds


async def diagnose(
    inp: DiagnosisInput,
    src: EvidenceSource | None = None,
    *,
    registry: Registry | None = None,
    now: datetime | None = None,
    metrics: Metrics | None = None,
) -> DiagnosisReport:
    t0 = time.perf_counter()
    m = metrics or NULL_METRICS
    now = now or datetime.now(UTC)
    reg = registry or default_registry()

    with track_masking() as masked:
        report = await _diagnose(inp, src, reg, now, m)

    dt = time.perf_counter() - t0
    m.observe("kdiag_diagnosis_duration_seconds", dt, mode=inp.mode)
    m.inc("kdiag_diagnosis_total", mode=inp.mode, status=report.status)
    if report.status == "unknown":
        m.inc("kdiag_unknown_cause_total", mode=inp.mode)
    if report.truncated:
        m.inc("kdiag_truncated_total")
    if masked[0]:
        m.inc("kdiag_masking_events_total", masked[0])
    m.observe("kdiag_report_bytes", float(len(report.model_dump_json())))
    for err in report.partial_errors:
        m.inc("kdiag_partial_reads_total", resource=err.resource.split(":")[0], reason=err.reason)
        if err.reason == "timeout":
            m.inc("kdiag_timeouts_total", resource=err.resource.split(":")[0])
    for rid in report.rule_errors:
        m.inc("kdiag_rule_exceptions_total", rule_id=rid.split(":")[0])
    for f in ([report.primary] if report.primary else []) + list(report.supporting):
        m.inc("kdiag_rule_matches_total", rule_id=f.rule_id)
    return report


async def _diagnose(
    inp: DiagnosisInput, src: EvidenceSource | None, reg: Registry, now: datetime, m: Metrics,
) -> DiagnosisReport:
    helm_text = "\n".join(t for t in (inp.helm_output, inp.job_log) if t)
    helm = helm_finding(parse_helm(helm_text))

    ev = Evidence(
        pods=inp.pods, events=inp.events, nodes=inp.nodes, pvcs=inp.pvcs, services=inp.services,
        jobs=inp.jobs, logs=inp.logs, namespace_phase=inp.namespace_phase,
        workload=inp.workload_status, available=frozenset(_supplied_kinds(inp)),
    )
    errors: list[PartialReadError] = []
    candidates: tuple[str, ...] = ()
    override: Status | None = None
    truncated = False

    if inp.mode != "evidence":
        if src is None or inp.target is None:
            raise ValueError("cluster and hybrid mode need an EvidenceSource and a target")
        target = inp.target
        collector = Collector(src, inp.limits, collect_logs=inp.collect_logs)
        try:
            async with asyncio.timeout(inp.limits.overall_timeout_s):
                refs = await collector.call("workload", lambda: src.find_workloads(target))
                if refs is None:
                    reasons = {e.reason for e in collector.errors}
                    override = ("cluster_unreachable" if reasons & {"unreachable", "timeout"}
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
        by_name = {p.name: p for p in ev.pods}
        by_name.update({p.name: p for p in got.pods})
        ev = ev.model_copy(update={
            "pods": tuple(by_name.values()), "events": ev.events + got.events,
            "nodes": ev.nodes + got.nodes, "pvcs": ev.pvcs + got.pvcs,
            "services": ev.services + got.services, "jobs": ev.jobs + got.jobs,
            "logs": ev.logs + got.logs,
            "namespace_phase": got.namespace_phase or ev.namespace_phase,
            "workload": got.workload or ev.workload,
            "available": ev.available | got.available,
        })
        truncated = got.truncated
        errors = list(collector.errors)

    pods, events, stale = normalize(ev.pods, ev.events, inp.window_start)
    ev = ev.model_copy(update={
        "pods": pods, "events": events, "stale_events_suppressed": stale,
        "workload": normalize_workload(ev.workload), "nodes": normalize_nodes(ev.nodes),
        "jobs": normalize_jobs(ev.jobs), "logs": normalize_logs(ev.logs),
        "partial_errors": tuple(errors), "truncated": truncated,
    })

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
