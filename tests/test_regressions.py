"""One test per defect found in the detailed review. Each failed before its fix."""
from __future__ import annotations

import time
from datetime import datetime

import pytest
from pydantic import ValidationError

from conftest import NOW, REF, cluster_input, ctr, ev_input, pod, pull_pod, run
from kdiag import (
    DiagnosisInput,
    EventEvidence,
    Limits,
    SourceError,
    Target,
    WorkloadStatus,
    diagnose,
    render_text,
)
from kdiag.helm import parse_helm
from kdiag.mask import mask_text
from kdiag.testing import FakeSource

PULL = 'Failed to pull image "registry.example.com/shop/web:2.4.1": manifest unknown'
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJlc2lnbmF0dXJl"


# --- masking ---------------------------------------------------------------------------------

def test_secret_straddling_truncation_boundary_is_not_half_leaked() -> None:
    out = mask_text(("x " * 985) + " " + JWT) or ""
    assert "eyJhbGciOiJIUzI1NiJ9" not in out


@pytest.mark.parametrize("line", [
    "DB_PASS=abc123xyz", "PWD=abc123xyz", "COOKIE: abc123xyz", "client_secret=abc123xyz",
    "Authorization: abc123xyz",
])
def test_common_secret_key_names_are_masked(line: str) -> None:
    assert "abc123xyz" not in (mask_text(line) or "")


def test_realistic_containerd_auth_error_still_classifies_after_masking() -> None:
    msg = ('Failed to pull image "r.io/a:1": failed to authorize: failed to fetch anonymous token: '
           "unexpected status: 401 Unauthorized")
    r = run(diagnose(ev_input(pods=(pull_pod(msg, reason="ErrImagePull"),)), now=NOW))
    assert r.primary and r.primary.sub_cause == "auth"


@pytest.mark.parametrize("text", ["a." * 2000, "a-" * 2000, "_" * 4000, "Aa0+" * 1000,
                                  "password" * 500, "a=" * 2000])
def test_mask_cost_stays_linear_on_adversarial_input(text: str) -> None:
    t0 = time.perf_counter()
    mask_text(text)
    assert time.perf_counter() - t0 < 0.25


# --- helm parser -----------------------------------------------------------------------------

def test_recovered_retry_earlier_in_log_is_not_the_failure() -> None:
    log = ("Error: UPGRADE FAILED: another operation (upgrade) is in progress\nretrying in 30s\n"
           'Release "shop" has been upgraded. Happy Helming!\n')
    r = parse_helm(log)
    assert r.kind == "unknown" and r.resolved == ("HLM-003:release_locked",)
    rep = run(diagnose(ev_input(pods=(pull_pod(PULL),), job_log=log), now=NOW))
    assert rep.primary and rep.primary.rule_id == "IMG-001"


def test_error_after_a_success_line_still_counts() -> None:
    log = 'Release "a" has been upgraded.\nError: UPGRADE FAILED: another operation (upgrade) is in progress'
    assert parse_helm(log).kind == "HLM-003"


def test_unrelated_parse_error_in_ci_noise_is_not_definitive() -> None:
    for noise in ("npm test: JSON parse error in fixtures.json", "SyntaxError: parse error at line 3",
                  "psql: yaml: line 4 something unrelated"):
        assert parse_helm(noise).kind == "unknown", noise
    assert parse_helm("Error: parse error at (chart/templates/x.yaml:5): bad").kind == "HLM-004"


def test_most_recent_definitive_error_wins() -> None:
    log = "Error: release: not found\nlater...\nError: cannot re-use a name that is still in use"
    assert parse_helm(log).kind == "HLM-005"


# --- collector / engine ----------------------------------------------------------------------

def test_overall_timeout_keeps_evidence_gathered_so_far() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)], delay={"list_events": 5})
    r = run(diagnose(cluster_input(limits=Limits(overall_timeout_s=0.3, request_timeout_s=10)),
                     src, now=NOW))
    assert r.status == "partial" and r.primary and r.primary.rule_id == "IMG-001"
    assert any(e.resource == "overall" for e in r.partial_errors)


def test_crashlooping_running_pod_survives_truncation() -> None:
    bad = pod("zz-bad", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1)])
    good = [pod(f"a{i:03}", containers=[ctr(ready=True)]) for i in range(60)]
    r = run(diagnose(cluster_input(limits=Limits(max_pods=10)), FakeSource([REF], pods=good + [bad]),
                     now=NOW))
    assert r.truncated and r.primary and r.primary.rule_id == "POD-004"


def test_mixed_naive_aware_and_missing_event_times_do_not_crash() -> None:
    ev = [EventEvidence(object_kind="Pod", object_name="p", timestamp=datetime(2026, 11, 21, 10, 0)),
          EventEvidence(object_kind="Pod", object_name="p", timestamp=NOW),
          EventEvidence(object_kind="Pod", object_name="p", timestamp=None)]
    r = run(diagnose(cluster_input(), FakeSource([REF], pods=[pull_pod(PULL)], events=ev), now=NOW))
    assert r.primary is not None


def test_healthy_pods_with_stuck_rollout_is_not_no_issue() -> None:
    stuck = WorkloadStatus(
        generation=5, observed_generation=5, replicas=3, updated_replicas=0, ready_replicas=3,
        available_replicas=3,
        conditions=(__import__("kdiag").Condition(
            type="ReplicaFailure", status="True", reason="FailedCreate",
            message="pods is forbidden: exceeded quota password=hunter2-canary"),))
    src = FakeSource([REF], pods=[pod(containers=[ctr(ready=True)])], status=stuck)
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "unknown" and r.primary is None
    assert r.notes[0].startswith("Rollout incomplete: 0/3 updated")
    assert any("ReplicaFailure" in n for n in r.notes)
    assert "hunter2" not in r.model_dump_json() and "NOTES" in render_text(r)


def test_healthy_pods_without_rollout_status_cannot_be_called_healthy() -> None:
    r = run(diagnose(ev_input(pods=(pod(containers=[ctr(ready=True)]),)), now=NOW))
    assert r.status == "unknown" and "rollout status was not available" in r.notes[0]


def test_workload_status_read_failure_is_reported_not_hidden() -> None:
    src = FakeSource([REF], pods=[pod(containers=[ctr(ready=True)])],
                     fail={"get_workload_status": SourceError("forbidden")})
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "partial"
    assert ("workload_status", "forbidden") in [(e.resource, e.reason) for e in r.partial_errors]


def test_unreachable_cluster_still_analyses_supplied_evidence() -> None:
    src = FakeSource([REF], fail={"find_workloads": SourceError("unreachable", retryable=True)})
    inp = DiagnosisInput(mode="hybrid", target=Target(name="shop-web", namespace="shop-prod"),
                         pods=(pull_pod(PULL),))
    r = run(diagnose(inp, src, now=NOW))
    assert r.status == "cluster_unreachable" and r.primary and r.primary.rule_id == "IMG-001"


# --- rules -----------------------------------------------------------------------------------

def test_markup_in_image_name_is_never_reflected() -> None:
    msg = 'Failed to pull image "<img src=x onerror=alert(1)>": not found'
    r = run(diagnose(ev_input(pods=(pull_pod(msg, reason="ErrImagePull"),)), now=NOW))
    assert r.primary and "<" not in r.primary.summary and "unknown" in r.primary.summary


def test_old_oom_on_a_running_container_is_low_confidence() -> None:
    p = pod(containers=[ctr(ready=True, last_terminated_reason="OOMKilled", restart_count=1)])
    r = run(diagnose(ev_input(pods=(p,)), now=NOW))
    assert r.primary and r.primary.sub_cause == "previous_oom" and r.primary.confidence == "low"


# --- input hardening -------------------------------------------------------------------------

def test_limits_have_hard_ceilings() -> None:
    for bad in ({"max_pods": -5}, {"max_pods": 10**6}, {"concurrency": 10**6},
                {"overall_timeout_s": 10**9}, {"request_timeout_s": 0},
                {"max_pods": 100, "max_pods_fetched": 50}):
        with pytest.raises(ValidationError):
            Limits(**bad)


@pytest.mark.parametrize("name", ["a,b", "x/../y", "a b", "x?y=1", "A_B", "-a", "a" * 300])
def test_target_names_must_be_dns_names(name: str) -> None:
    with pytest.raises(ValidationError):
        Target(name=name)
    with pytest.raises(ValidationError):
        Target(name="ok", namespace=name)


def test_oversized_evidence_lists_are_rejected() -> None:
    with pytest.raises(ValidationError):
        DiagnosisInput(mode="evidence", pods=tuple(pod(f"p{i}") for i in range(501)))
    with pytest.raises(ValidationError):
        DiagnosisInput(mode="evidence", events=tuple(
            EventEvidence(object_kind="Pod", object_name="p") for _ in range(5001)))
