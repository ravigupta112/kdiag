"""CI gate: every item of the 173-item master list is mapped, and executable samples still hit."""
from __future__ import annotations

import pathlib

import pytest
import yaml

from conftest import NOW, ctr, pod, run
from kdiag import DiagnosisInput, diagnose
from kdiag.helm import PATTERNS
from kdiag.models import (
    Condition,
    ContainerLog,
    EventEvidence,
    JobEvidence,
    NodeEvidence,
    PvcEvidence,
    WorkloadStatus,
)
from kdiag.rules import default_registry

DOC = yaml.safe_load((pathlib.Path(__file__).parent.parent / "coverage_map.yaml").read_text())
ALLOWED = {"INFO", "SYMPTOM", "STATUS", "SOURCE_ERROR", "NOT_IMPLEMENTED", "OUT_OF_SCOPE"}
TOTAL = 173


def expand(spec: str) -> list[int]:
    out: list[int] = []
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def test_every_item_is_mapped_exactly_once() -> None:
    seen: dict[int, str] = {}
    entries = [(rid, spec) for rid, spec in DOC["rules"].items()]
    entries += [(f"disp:{k}", v["items"]) for k, v in DOC["dispositions"].items()]
    for owner, spec in entries:
        for n in expand(spec):
            assert n not in seen, f"item {n} mapped to both {seen[n]} and {owner}"
            seen[n] = owner
    assert set(seen) == set(range(1, TOTAL + 1)), sorted(set(range(1, TOTAL + 1)) - set(seen))


def test_rule_ids_exist_and_dispositions_are_known() -> None:
    known = {r.id for r in default_registry().all()} | {p.id for p in PATTERNS}
    assert set(DOC["rules"]) <= known, set(DOC["rules"]) - known
    assert set(DOC["dispositions"]) <= ALLOWED
    for d in DOC["dispositions"].values():
        assert d["reason"]


def test_coverage_numbers_are_honest() -> None:
    mapped = sum(len(expand(s)) for s in DOC["rules"].values())
    gaps = len(expand(DOC["dispositions"]["NOT_IMPLEMENTED"]["items"]))
    print(f"\nrules cover {mapped}/{TOTAL}; not implemented {gaps}")
    assert mapped >= 100 and gaps <= 30


def build(s: dict) -> DiagnosisInput:
    via, text = s["via"], s.get("text", "")
    if via == "waiting":
        p = pod(phase="Pending", containers=[ctr(waiting_reason=s["reason"], waiting_message=text)])
        return DiagnosisInput(mode="evidence", pods=(p,))
    if via == "sched":
        p = pod(phase="Pending", conditions=[Condition(type="PodScheduled", status="False", reason="Unschedulable", message=text)])
        return DiagnosisInput(mode="evidence", pods=(p,))
    if via == "oom":
        return DiagnosisInput(mode="evidence", pods=(pod(containers=[ctr(waiting_reason="CrashLoopBackOff", last_terminated_reason="OOMKilled")]),))
    if via == "crashloop":
        return DiagnosisInput(mode="evidence", pods=(pod(containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1)]),))
    if via == "pod_evicted":
        p = pod(phase="Failed").model_copy(update={"reason": "Evicted", "message": text})
        return DiagnosisInput(mode="evidence", pods=(p,))
    if via == "event":
        e = EventEvidence(object_kind=s["kind"], object_name="x", type="Warning", reason=s["reason"], message=text, timestamp=NOW)
        return DiagnosisInput(mode="evidence", events=(e,), pods=(pod(phase="Pending"),))
    if via == "pvc":
        e = EventEvidence(object_kind="PersistentVolumeClaim", object_name="data", type="Warning", reason=s["reason"], message=text, timestamp=NOW)
        return DiagnosisInput(mode="evidence", events=(e,), pvcs=(PvcEvidence(name="data", namespace="n", phase="Pending"),))
    if via == "node":
        status = "False" if s["cond"] == "Ready" else "True"
        n = NodeEvidence(name="n1", conditions=(Condition(type=s["cond"], status=status),))
        return DiagnosisInput(mode="evidence", nodes=(n,), pods=(pod(),))
    if via == "job":
        j = JobEvidence(name="j", namespace="n", conditions=(Condition(type="Failed", status="True", reason=s["reason"]),))
        return DiagnosisInput(mode="evidence", jobs=(j,), pods=(pod(),))
    if via == "workload":
        ws = WorkloadStatus(conditions=(Condition(type=s["cond"], status="True" if s["cond"] == "ReplicaFailure" else "False", reason=s["reason"]),))
        return DiagnosisInput(mode="evidence", workload_status=ws, pods=(pod(),))
    if via == "log":
        lg = ContainerLog(pod="p", container="web", previous=True, lines=(text,))
        return DiagnosisInput(mode="evidence", logs=(lg,), pods=(pod(),))
    if via == "helm":
        return DiagnosisInput(mode="evidence", helm_output=text)
    raise AssertionError(via)


@pytest.mark.parametrize("sample", DOC["samples"], ids=lambda s: f"item{s['item']}-{s['expect']}")
def test_samples_produce_the_expected_finding(sample: dict) -> None:
    rule, sub = sample["expect"].split("/")
    r = run(diagnose(build(sample), now=NOW))
    findings = ([r.primary] if r.primary else []) + list(r.supporting)
    assert (rule, sub) in {(f.rule_id, f.sub_cause) for f in findings}, [(f.rule_id, f.sub_cause) for f in findings]
    assert sample["item"] in expand(DOC["rules"][rule]), f"item {sample['item']} not mapped to {rule}"
