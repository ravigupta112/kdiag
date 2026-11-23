from __future__ import annotations

from types import SimpleNamespace as NS

from fakek8s import cstatus, v1event, v1pod
from kdiag.k8s import convert as cv


def test_pod_conversion_captures_status_never_env() -> None:
    p = v1pod("web-1", containers=[cstatus(False, 3, ("CrashLoopBackOff", "back-off"),
                                           last_term=(137, "OOMKilled", "killed"))],
              mem="512Mi", env_secret="hunter2-canary-value", claims=("data", "cache"), reason=None)
    ev = cv.pod_from_v1(p)
    dump = ev.model_dump_json()
    assert "hunter2" not in dump and "DB_PASSWORD" not in dump
    c = ev.containers[0]
    assert (c.waiting_reason, c.last_terminated_reason, c.last_exit_code, c.restart_count) == (
        "CrashLoopBackOff", "OOMKilled", 137, 3)
    assert c.memory_limit == "512Mi" and ev.pvc_claims == ("cache", "data") and ev.node_name == "node-1"


def test_event_time_precedence_and_unknown_stays_none() -> None:
    from datetime import datetime
    e = v1event("Pod", "p", "X", "m", last="2026-11-21T10:05:00")
    assert cv.event_time(e) == datetime(2026, 11, 21, 10, 5)
    assert cv.event_time(v1event("Pod", "p", "X", "m")) is None
    series = NS(series=NS(last_observed_time="S"), last_timestamp="L", event_time="E", first_timestamp="F")
    assert cv.event_time(series) == "S"
    assert cv.event_time(NS(series=None, last_timestamp=None, event_time="E", first_timestamp="F")) == "E"


def test_endpoint_counts_nil_ready_means_ready() -> None:
    sl = NS(endpoints=[NS(conditions=NS(ready=None)), NS(conditions=NS(ready=True)),
                       NS(conditions=NS(ready=False)), NS(conditions=None)])
    assert cv.endpoint_counts([sl]) == (3, 1)
    assert cv.endpoint_counts([]) == (0, 0)


def test_statefulset_without_available_replicas_falls_back_to_ready() -> None:
    sts = NS(metadata=NS(generation=2), spec=NS(replicas=3),
             status=NS(observed_generation=2, updated_replicas=3, ready_replicas=3, available_replicas=None,
                       conditions=None))
    ws = cv.workload_status_from_v1(sts)
    assert ws.available_replicas == 3 and ws.replicas == 3


def test_zero_replicas_is_preserved_not_defaulted() -> None:
    d = NS(metadata=NS(generation=1), spec=NS(replicas=0), status=NS(observed_generation=1))
    assert cv.workload_status_from_v1(d).replicas == 0
