"""Scenario tests S1-S12 from the PRD."""
from __future__ import annotations

from datetime import timedelta

from conftest import (
    NOW,
    REF,
    cluster_input,
    ctr,
    ev_input,
    event,
    pod,
    pull_pod,
    run,
    unschedulable,
)
from kdiag import (
    Limits,
    SourceError,
    WorkloadRef,
    diagnose,
    render_text,
)
from kdiag.models import Condition, WorkloadStatus
from kdiag.normalize import normalize
from kdiag.rules import Registry, default_registry
from kdiag.testing import FakeSource

PULL = 'Failed to pull image "registry.example.com/shop/web:2.4.1": not found'
OOM_POD = pod(containers=[ctr(last_terminated_reason="OOMKilled", restart_count=3,
                              waiting_reason="CrashLoopBackOff", memory_limit="512Mi")])


def test_s1_image_not_found_cluster_mode() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)])
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "diagnosed" and r.primary
    assert (r.primary.rule_id, r.primary.sub_cause, r.primary.confidence) == ("IMG-001", "not_found", "high")
    assert r.partial_errors == () and r.collected_at == NOW


def test_s1_evidence_mode_needs_no_source() -> None:
    r = run(diagnose(ev_input(pods=(pull_pod(PULL),)), now=NOW))
    assert r.primary and r.primary.rule_id == "IMG-001"


def test_s2_oom_is_primary_and_crashloop_not_duplicated() -> None:
    r = run(diagnose(ev_input(pods=(OOM_POD,)), now=NOW))
    assert r.primary and r.primary.rule_id == "POD-005" and r.supporting == ()


def test_s3_taint() -> None:
    msg = "0/3 nodes are available: 3 node(s) had untolerated taint {dedicated: gpu}."
    r = run(diagnose(ev_input(pods=(unschedulable(msg),)), now=NOW))
    assert r.primary and (r.primary.rule_id, r.primary.sub_cause) == ("SCHED-001", "taint")


def test_s5_helm_lock_is_definitive_and_cluster_findings_support() -> None:
    inp = ev_input(pods=(OOM_POD,), helm_output="Error: another operation (upgrade) is in progress")
    r = run(diagnose(inp, now=NOW))
    assert r.primary and r.primary.rule_id == "HLM-003"
    assert [f.rule_id for f in r.supporting] == ["POD-005"]


def test_s6_two_causes_earliest_in_chain_wins_and_both_reported() -> None:
    crash = pod("shop-web-3", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1)])
    msg = "0/3 nodes are available: 3 Insufficient cpu."
    r = run(diagnose(ev_input(pods=(unschedulable(msg), crash)), now=NOW))
    assert r.primary and r.primary.rule_id == "SCHED-001"
    assert [f.rule_id for f in r.supporting] == ["POD-004"]


def test_helm_timeout_alone_is_unknown_not_a_cause() -> None:
    inp = ev_input(helm_output="Error: UPGRADE FAILED: timed out waiting for the condition")
    r = run(diagnose(inp, now=NOW))
    assert r.status == "unknown" and r.primary is None
    assert [f.rule_id for f in r.supporting] == ["HLM-001"]


def test_helm_timeout_plus_cluster_cause_cluster_wins() -> None:
    inp = ev_input(pods=(pull_pod(PULL),),
                   helm_output="Error: UPGRADE FAILED: timed out waiting for the condition")
    r = run(diagnose(inp, now=NOW))
    assert r.primary and r.primary.rule_id == "IMG-001"
    assert [f.rule_id for f in r.supporting] == ["HLM-001"]


def test_s7_ambiguous_target_does_not_guess() -> None:
    other = WorkloadRef(kind="Deployment", name="shop-web", namespace="shop-staging")
    src = FakeSource([REF, other], pods=[pull_pod(PULL)])
    inp = cluster_input()
    inp = inp.model_copy(update={"target": inp.target.model_copy(update={"namespace": None})})
    r = run(diagnose(inp, src, now=NOW))
    assert r.status == "ambiguous_target" and r.primary is None
    assert r.candidates == ("shop-prod/Deployment/shop-web", "shop-staging/Deployment/shop-web")
    assert "list_pods" not in src.calls


def test_s8_target_not_found() -> None:
    r = run(diagnose(cluster_input(), FakeSource([]), now=NOW))
    assert r.status == "target_not_found"


def test_s9_forbidden_events_is_partial_but_keeps_finding() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)], fail={"list_events": SourceError("forbidden")})
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "partial" and r.primary and r.primary.rule_id == "IMG-001"
    assert [(e.resource, e.reason) for e in r.partial_errors] == [("events", "forbidden")]


def test_s9_forbidden_pods_skips_rules_instead_of_reporting_clean() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)], fail={"list_pods": SourceError("forbidden")})
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "partial" and r.primary is None
    skipped = {s.rule_id for s in r.skipped_rules if "pods" in s.missing}
    assert {"IMG-001", "POD-004", "POD-005", "SCHED-001", "CFG-001"} <= skipped
    assert "needs pods:" in render_text(r)


def test_s10_cluster_unreachable() -> None:
    src = FakeSource([REF], fail={"find_workloads": SourceError("unreachable", retryable=True)})
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "cluster_unreachable" and r.partial_errors[0].retryable


def test_s11_healthy_needs_pods_and_a_completed_rollout() -> None:
    healthy = pod(containers=[ctr(ready=True)])
    ws = WorkloadStatus(generation=3, observed_generation=3, replicas=1, updated_replicas=1,
                        ready_replicas=1, available_replicas=1)
    r = run(diagnose(ev_input(pods=(healthy,), workload_status=ws), now=NOW))
    assert r.status == "no_issue_detected" and r.primary is None


def test_s12_unmatched_is_unknown_and_nothing_is_invented() -> None:
    r = run(diagnose(ev_input(pods=(pod(phase="Pending"),)), now=NOW))
    assert r.status == "unknown" and r.primary is None and r.supporting == ()


def test_request_timeout_is_partial_and_retryable() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)], delay={"list_pods": 0.3})
    r = run(diagnose(cluster_input(limits=Limits(request_timeout_s=0.05)), src, now=NOW))
    assert r.status == "partial"
    assert any(e.resource == "pods" and e.reason == "timeout" and e.retryable for e in r.partial_errors)


def test_overall_deadline_is_enforced() -> None:
    src = FakeSource([REF], delay={"find_workloads": 5})
    r = run(diagnose(cluster_input(limits=Limits(overall_timeout_s=0.05)), src, now=NOW))
    assert r.status == "partial"
    assert any(e.resource == "overall" and e.reason == "timeout" for e in r.partial_errors)


def test_unexpected_source_exception_does_not_leak_its_text() -> None:
    class Boom(FakeSource):
        async def list_pods(self, ref, limit):
            raise RuntimeError("token=SUPERSECRETCANARY")

    r = run(diagnose(cluster_input(), Boom([REF]), now=NOW))
    assert "SUPERSECRETCANARY" not in r.model_dump_json()
    assert r.partial_errors[0].reason == "error"


def test_rule_exception_is_isolated_and_recorded() -> None:
    class Bad:
        id, priority, requires = "BAD-001", 1, frozenset({"pods"})

        def evaluate(self, ev):
            raise ValueError("password=hunter2")

    reg = default_registry()
    reg.register(Bad())
    r = run(diagnose(ev_input(pods=(pull_pod(PULL),)), registry=reg, now=NOW))
    assert r.primary and r.primary.rule_id == "IMG-001"
    assert r.rule_errors == ("BAD-001: ValueError",) and "hunter2" not in r.model_dump_json()


def test_duplicate_rule_ids_rejected() -> None:
    import pytest
    reg = Registry()
    rule = default_registry().all()[0]
    reg.register(rule)
    with pytest.raises(ValueError):
        reg.register(rule)


def test_pod_cap_truncates_deterministically_failing_first() -> None:
    pods = [pod(f"ok-{i:03}", containers=[ctr(ready=True)]) for i in range(60)] + [pull_pod(PULL, name="bad")]
    r = run(diagnose(cluster_input(limits=Limits(max_pods=10)), FakeSource([REF], pods=pods), now=NOW))
    assert r.truncated and r.primary and r.primary.rule_id == "IMG-001"


def test_report_size_cap_trims_supporting_and_flags_truncation() -> None:
    pods = tuple(pull_pod(PULL + f" variant {i}", name=f"p{i}") for i in range(5))
    pods += (unschedulable("0/3 nodes are available: 3 Insufficient cpu."),
             pod("c", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=2)]))
    r = run(diagnose(ev_input(pods=pods, limits=Limits(max_report_bytes=1200)), now=NOW))
    assert r.truncated
    assert len(r.model_dump_json()) <= 1200 or r.supporting == ()


def test_stale_events_suppressed_and_missing_timestamps_flagged() -> None:
    old, fresh = event(ts=NOW - timedelta(hours=2)), event(ts=NOW)
    undated = event(ts=None)
    _, events, stale = normalize((), (old, fresh, undated), NOW - timedelta(minutes=5))
    assert stale == 1 and len(events) == 2
    assert [e.time_unknown for e in events] == [False, True]
    naive = event(ts=NOW.replace(tzinfo=None))
    _, events, _ = normalize((), (naive,), None)
    assert events[0].timestamp.tzinfo is not None


def test_determinism_same_input_same_report() -> None:
    pods = (pull_pod(PULL), unschedulable("0/3 nodes are available: 3 Insufficient cpu."), OOM_POD)
    a = run(diagnose(ev_input(pods=pods), now=NOW)).model_dump_json()
    b = run(diagnose(ev_input(pods=pods), now=NOW)).model_dump_json()
    assert a == b


def test_canary_secrets_never_reach_report_or_text() -> None:
    dirty = pull_pod('Failed to pull image "registry.example.com/shop/web:2.4.1": unauthorized '
                     'password=hunter2-canary Authorization: Bearer canarytoken1234567890')
    cond = Condition(type="PodScheduled", status="False", reason="Unschedulable",
                     message="0/3 nodes are available: 3 Insufficient cpu. token=canary-sched")
    inp = ev_input(pods=(dirty, pod("p2", "Pending", conditions=[cond])),
                   helm_output="Error: release: not found api_key=canary-helm")
    r = run(diagnose(inp, now=NOW))
    blob = r.model_dump_json() + render_text(r)
    assert "canary" not in blob.lower() and "hunter2" not in blob


def test_render_text_answer_first() -> None:
    r = run(diagnose(ev_input(pods=(pull_pod(PULL),)), now=NOW))
    lines = render_text(r).splitlines()
    assert lines[0].startswith("DIAGNOSED") and lines[1].startswith("CAUSE") and lines[3].startswith("NEXT")
