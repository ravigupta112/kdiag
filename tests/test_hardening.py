"""Performance, load, failure-injection, fuzz and consistency tests (Phase 6)."""
from __future__ import annotations

import json
import pathlib
import re
import time
import tracemalloc

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import NOW, REF, cluster_input, ctr, ev_input, pod, pull_pod, run
from kdiag import (
    EventEvidence,
    InMemoryMetrics,
    Limits,
    SourceError,
    diagnose,
)
from kdiag.helm import parse_helm
from kdiag.observability import METRIC_NAMES, PrometheusMetrics
from kdiag.service import ServiceSettings
from kdiag.store import SqliteStore
from kdiag.testing import FakeSource
from svc_helpers import (
    CLUSTER,
    TOKENS,
    client,
    hdr,
    make_env,
    run_all,
)

ROOT = pathlib.Path(__file__).parent.parent
PULL = 'Failed to pull image "registry.example.com/shop/web:2.4.1": manifest unknown'


# ---- performance ----------------------------------------------------------------------------------

def test_large_workload_stays_bounded_in_time_memory_and_size() -> None:
    pods = [pull_pod(PULL, name=f"a-bad-{i}") for i in range(3)]  # sort first: inside the fetch ceiling
    pods += [pod(f"ok-{i:04}", containers=[ctr(ready=True)]) for i in range(600)]
    events = [EventEvidence(object_kind="Pod", object_name="x", reason="Failed", message=PULL, timestamp=NOW)
              for _ in range(20_000)]
    tracemalloc.start()
    t0 = time.perf_counter()
    r = run(diagnose(cluster_input(), FakeSource([REF], pods=pods, events=events), now=NOW))
    elapsed, (_, peak) = time.perf_counter() - t0, tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert r.truncated and r.primary and r.primary.rule_id == "IMG-001"
    assert elapsed < 3.0 and peak < 150_000_000
    assert len(r.model_dump_json()) <= Limits().max_report_bytes


def test_truncated_evidence_is_never_called_healthy() -> None:
    # failing pods sort after the fetch ceiling, so they are never seen: the report must not say "fine"
    pods = [pod(f"ok-{i:04}", containers=[ctr(ready=True)]) for i in range(600)]
    pods += [pull_pod(PULL, name=f"zz-bad-{i}") for i in range(3)]
    r = run(diagnose(cluster_input(), FakeSource([REF], pods=pods), now=NOW))
    assert r.truncated and r.status == "unknown" and r.primary is None
    assert any("truncated" in n for n in r.notes)


def test_megabyte_job_logs_parse_quickly() -> None:
    noise = ("2026-11-21T10:00:00Z \x1b[32mstep ok\x1b[0m   building layer abc123\n" * 20_000)[:1_000_000]
    t0 = time.perf_counter()
    r = parse_helm(noise + "\nError: UPGRADE FAILED: another operation (upgrade) is in progress")
    assert r.kind == "HLM-003" and time.perf_counter() - t0 < 2.0


def test_overall_deadline_bounds_response_time_even_with_a_hung_source() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)], delay={"find_workloads": 30})
    t0 = time.perf_counter()
    r = run(diagnose(cluster_input(limits=Limits(overall_timeout_s=0.3, request_timeout_s=60)), src, now=NOW))
    assert time.perf_counter() - t0 < 1.5 and r.status == "partial"


# ---- load -----------------------------------------------------------------------------------------

def test_burst_of_requests_completes_without_errors_when_capacity_allows() -> None:
    env = make_env(ServiceSettings(max_concurrent=8, queue_wait_s=10, rate_per_s=10_000, rate_burst=10_000))

    async def one(i: int):
        async with client(env) as c:
            return await c.post("/v1/diagnose", json=CLUSTER | {"job_id": f"j{i}", "refresh": True},
                                headers=hdr("tok-a"))

    t0 = time.perf_counter()
    rs = run_all(*[one(i) for i in range(120)])
    assert {r.status_code for r in rs} == {200} and time.perf_counter() - t0 < 10


def test_overload_sheds_load_with_503_never_500_and_never_hangs() -> None:
    env = make_env(ServiceSettings(max_concurrent=2, queue_wait_s=0.05, rate_per_s=10_000, rate_burst=10_000),
                   a_delay=0.3)

    async def one(i: int):
        async with client(env) as c:
            return await c.post("/v1/diagnose", json=CLUSTER | {"job_id": f"j{i}", "refresh": True},
                                headers=hdr("tok-a"))

    t0 = time.perf_counter()
    rs = run_all(*[one(i) for i in range(30)])
    codes = [r.status_code for r in rs]
    assert set(codes) <= {200, 503} and 200 in codes and 503 in codes
    assert time.perf_counter() - t0 < 5 and all(r.headers.get("retry-after") for r in rs if r.status_code == 503)


# ---- failure injection ----------------------------------------------------------------------------

METHODS = ["find_workloads", "get_workload_status", "list_pods", "list_events", "get_nodes", "list_pvcs",
           "list_services", "list_jobs", "get_namespace_phase", "get_logs"]
ERRORS = [SourceError("forbidden"), SourceError("not_found"), SourceError("timeout", retryable=True),
          SourceError("unreachable", retryable=True), SourceError("rate_limited", retryable=True),
          SourceError("error"), RuntimeError("password=hunter2-canary")]


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("error", ERRORS, ids=lambda e: f"{type(e).__name__}-{getattr(e, 'reason', 'x')}")
def test_any_single_source_failure_never_crashes_and_never_leaks(method: str, error: Exception) -> None:
    crash = pod("shop-web-9", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1, restart_count=2)],
                ).model_copy(update={"node_name": "n1", "pvc_claims": ("data",)})
    src = FakeSource([REF], pods=[pull_pod(PULL), crash])
    src.fail[method] = error  # type: ignore[assignment]
    r = run(diagnose(cluster_input(collect_logs=True), src, now=NOW))
    assert r.status in {"diagnosed", "partial", "cluster_unreachable", "target_not_found", "unknown"}
    assert "hunter2" not in r.model_dump_json()
    if method == "find_workloads":
        assert r.status in {"cluster_unreachable", "target_not_found", "partial"}
    else:
        assert r.primary is not None or any(e.resource.split(":")[0] in {"pods", "events"} for e in r.partial_errors)


def test_object_disappearing_mid_collection_is_a_reported_gap_not_a_crash() -> None:
    src = FakeSource([REF], pods=[pull_pod(PULL)], fail={"get_workload_status": SourceError("not_found"),
                                                          "list_events": SourceError("not_found")})
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "partial" and r.primary and r.primary.rule_id == "IMG-001"
    assert {(e.resource, e.reason) for e in r.partial_errors} == {("workload_status", "not_found"), ("events", "not_found")}


def test_optional_cluster_scope_reads_do_not_downgrade_the_status() -> None:
    crash = pod("c", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1)]).model_copy(update={"node_name": "n1"})
    src = FakeSource([REF], pods=[crash], fail={"get_nodes": SourceError("forbidden"),
                                                 "get_namespace_phase": SourceError("forbidden")})
    r = run(diagnose(cluster_input(), src, now=NOW))
    assert r.status == "diagnosed" and {e.resource for e in r.partial_errors} == {"nodes", "namespace"}
    assert all(e.optional for e in r.partial_errors)


# ---- fuzz: the HTTP surface never returns 5xx -----------------------------------------------------

json_leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=40), st.floats(allow_nan=False))
json_val = st.recursive(json_leaf, lambda c: st.one_of(st.lists(c, max_size=4), st.dictionaries(st.text(max_size=12), c, max_size=4)), max_leaves=12)
FIELDS = ["mode", "cluster_id", "target", "namespace", "release", "pods", "events", "nodes", "jobs", "logs",
          "helm_output", "job_log", "include_logs", "job_id", "save", "refresh", "kubeconfig", "export", "window_start"]


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
@given(st.dictionaries(st.sampled_from(FIELDS), json_val, max_size=6), st.sampled_from(["evidence", "cluster", "hybrid", "x"]))
def test_fuzzed_request_bodies_never_cause_a_server_error(body: dict, mode: str) -> None:
    env = _FUZZ_ENV
    async def go():
        async with client(env) as c:
            return await c.post("/v1/diagnose", json={"mode": mode, **body}, headers=hdr("tok-a-admin"))
    r = run(go())
    assert r.status_code < 500 or r.status_code in (502, 504), (r.status_code, r.text[:200])
    assert r.json()["meta"]["request_id"]
    json.dumps(r.json())


_FUZZ_ENV = make_env(ServiceSettings(rate_per_s=10**6, rate_burst=10**6))


@settings(max_examples=40, deadline=None)
@given(st.lists(st.tuples(st.sampled_from(["tA", "tB", "tC"]), st.sampled_from(["j1", "j2", None])), min_size=1, max_size=12))
def test_property_a_tenant_can_never_read_another_tenants_report(saves: list[tuple[str, str | None]]) -> None:
    s = SqliteStore()
    rep = run(diagnose(ev_input(pods=(pull_pod(PULL),)), now=NOW))
    ids = [(t, run(s.save(t, "c", rep, job_id=j)).id) for t, j in saves]
    for owner, rid in ids:
        for other in {"tA", "tB", "tC"} - {owner}:
            assert run(s.get(other, rid)) is None
        assert run(s.get(owner, rid)) is not None


# ---- observability / docs consistency -------------------------------------------------------------

def test_diagnosis_emits_the_documented_metrics() -> None:
    m = InMemoryMetrics()
    crash = pod("c", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1)])
    dirty = pull_pod(PULL + " password=hunter2-canary", name="d")
    src = FakeSource([REF], pods=[crash, dirty], fail={"list_events": SourceError("timeout", retryable=True)})
    run(diagnose(cluster_input(), src, now=NOW, metrics=m))
    run(diagnose(ev_input(pods=(pod(phase="Pending"),)), now=NOW, metrics=m))

    class Bad:
        id, priority, requires = "BAD-1", 1, frozenset({"pods"})

        def evaluate(self, ev):
            raise ValueError("x")

    from kdiag.rules import default_registry
    reg = default_registry()
    reg.register(Bad())
    run(diagnose(ev_input(pods=(crash,)), registry=reg, now=NOW, metrics=m))
    names = {n for (n, _) in m.counters} | set(m.observations)
    for expected in ("kdiag_diagnosis_total", "kdiag_diagnosis_duration_seconds", "kdiag_unknown_cause_total",
                     "kdiag_partial_reads_total", "kdiag_timeouts_total", "kdiag_rule_matches_total",
                     "kdiag_rule_exceptions_total", "kdiag_masking_events_total", "kdiag_report_bytes"):
        assert expected in names, expected
    assert m.count("kdiag_rule_exceptions_total", rule_id="BAD-1") == 1
    assert m.count("kdiag_partial_reads_total", resource="events", reason="timeout") == 1


def test_every_metric_in_code_alerts_and_docs_is_declared() -> None:
    declared = set(METRIC_NAMES)
    in_code = set(re.findall(r'"(kdiag_[a-z0-9_]+)"', "\n".join(p.read_text() for p in (ROOT / "src").rglob("*.py"))))
    assert in_code <= declared, in_code - declared
    never_emitted = declared - in_code
    assert not never_emitted, never_emitted
    alerts = yaml.safe_load((ROOT / "deploy" / "alerts.yaml").read_text())
    expr = " ".join(r["expr"] for g in alerts["groups"] for r in g["rules"])
    used = {re.sub(r"_(bucket|sum|count)$", "", n) for n in re.findall(r"kdiag_[a-z0-9_]+", expr)}
    assert used <= declared, used - declared
    doc = (ROOT / "docs" / "OPERATIONS.md").read_text()
    assert set(re.findall(r"kdiag_[a-z0-9_]+", doc)) <= declared | {"kdiag_diagnosis_duration_seconds_bucket"}
    for g in alerts["groups"]:
        for rule in g["rules"]:
            anchor = rule["annotations"]["runbook"].split("#")[1]
            assert f"(#{anchor})" in doc or f"{{#{anchor}}}" in doc or anchor.replace("-", " ") in doc.lower()


def test_prometheus_adapter_exports_and_rejects_inconsistent_labels() -> None:
    from prometheus_client import CollectorRegistry, generate_latest
    reg = CollectorRegistry()
    pm = PrometheusMetrics(registry=reg)
    pm.inc("kdiag_diagnosis_total", mode="cluster", status="diagnosed")
    pm.observe("kdiag_diagnosis_duration_seconds", 0.2, mode="cluster")
    text = generate_latest(reg).decode()
    assert 'kdiag_diagnosis_total{mode="cluster",status="diagnosed"} 1.0' in text
    assert "kdiag_diagnosis_duration_seconds_bucket" in text
    with pytest.raises(ValueError):
        pm.inc("kdiag_diagnosis_total", mode="cluster")


def test_alert_rules_are_valid_yaml_with_runbooks() -> None:
    alerts = yaml.safe_load((ROOT / "deploy" / "alerts.yaml").read_text())
    rules = [r for g in alerts["groups"] for r in g["rules"]]
    assert len(rules) >= 8 and len({r["alert"] for r in rules}) == len(rules)
    for r in rules:
        assert r["expr"] and r["labels"]["severity"] in {"page", "ticket"} and r["annotations"]["runbook"]


def test_tokens_fixture_sanity() -> None:
    assert len({p.tenant_id for p in TOKENS.values()}) == 2
