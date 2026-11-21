from __future__ import annotations

import pytest

from conftest import ctr, event, pod, pull_pod, unschedulable
from kdiag.models import Evidence
from kdiag.rules.crashloop import CrashLoopRule
from kdiag.rules.image import ImageRule
from kdiag.rules.oom import OOMKilledRule
from kdiag.rules.sched import UnschedulableRule


def ev(*pods, events=()):
    return Evidence(pods=tuple(pods), events=tuple(events), available=frozenset({"pods", "events"}))


PULL = 'Failed to pull image "registry.example.com/shop/web:2.4.1": '


@pytest.mark.parametrize(("msg", "sub", "conf"), [
    (PULL + "rpc error: code = NotFound desc = failed to resolve reference: not found",
     "not_found", "high"),
    (PULL + "manifest unknown", "not_found", "high"),
    (PULL + "unauthorized: authentication required", "auth", "high"),
    (PULL + "pull access denied, repository does not exist or may require authorization",
     "auth_or_not_found", "medium"),
    (PULL + "net/http: TLS handshake timeout", "network", "medium"),
    (PULL + "something nobody has seen before", "generic", "low"),
])
def test_image_subcauses(msg: str, sub: str, conf: str) -> None:
    (f,) = ImageRule().evaluate(ev(pull_pod(msg)))
    assert (f.rule_id, f.sub_cause, f.confidence) == ("IMG-001", sub, conf)
    assert f.details["image"] == "registry.example.com/shop/web:2.4.1"


def test_image_reason_driven_subcauses_and_negative() -> None:
    (f,) = ImageRule().evaluate(ev(pull_pod("", reason="InvalidImageName")))
    assert f.sub_cause == "invalid_name"
    assert ImageRule().evaluate(ev(pod(containers=[ctr(ready=True)]))) == []


def test_image_uses_pod_events_when_status_message_is_empty() -> None:
    p = pull_pod("")
    e = event("Failed", PULL + "manifest unknown")
    (f,) = ImageRule().evaluate(ev(p, events=[e]))
    assert f.sub_cause == "not_found"


def test_image_groups_pods_by_subcause() -> None:
    pods = [pull_pod(PULL + "manifest unknown", name=f"p{i}") for i in range(3)]
    (f,) = ImageRule().evaluate(ev(*pods))
    assert len(f.evidence_refs) == 3


def test_oom_positive_negative_and_limit() -> None:
    c = ctr(last_terminated_reason="OOMKilled", restart_count=4, memory_limit="512Mi")
    (f,) = OOMKilledRule().evaluate(ev(pod(containers=[c])))
    assert f.confidence == "high" and "512Mi" in f.summary and f.details["restarts"] == "4"
    only_137 = ctr(last_terminated_reason="Error", last_exit_code=137)
    assert OOMKilledRule().evaluate(ev(pod(containers=[only_137]))) == []  # exit 137 alone is not proof


def test_crashloop_reports_loop_not_cause_and_defers_to_oom() -> None:
    c = ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1, restart_count=7)
    (f,) = CrashLoopRule().evaluate(ev(pod(containers=[c])))
    assert f.sub_cause == "exit_1" and "previous container logs" in f.next_action
    oom = ctr(waiting_reason="CrashLoopBackOff", last_terminated_reason="OOMKilled")
    assert CrashLoopRule().evaluate(ev(pod(containers=[oom]))) == []


@pytest.mark.parametrize(("msg", "sub"), [
    ("0/3 nodes are available: 3 node(s) had untolerated taint {dedicated: gpu}.", "taint"),
    ("0/3 nodes are available: 3 Insufficient cpu.", "insufficient"),
    ("0/3 nodes are available: 1 Insufficient memory, 2 node(s) didn't match Pod's node affinity/selector.",
     "affinity"),
    ("0/3 nodes are available: 1 node(s) had untolerated taint {a: b}, 2 Insufficient cpu.",
     "insufficient"),
    ("0/4 nodes are available: 4 node(s) didn't match pod topology spread constraints.", "topology"),
    ("0/3 nodes are available: 3 node(s) didn't match pod anti-affinity rules.", "anti_affinity"),
    ("0/3 nodes are available: pod has unbound immediate PersistentVolumeClaims.", "unbound_pvc"),
    ("something completely different", "unclassified"),
])
def test_sched_subcauses(msg: str, sub: str) -> None:
    (f,) = UnschedulableRule().evaluate(ev(unschedulable(msg)))
    assert f.rule_id == "SCHED-001" and f.sub_cause == sub


def test_sched_ignores_scheduled_pods() -> None:
    assert UnschedulableRule().evaluate(ev(pod())) == []
