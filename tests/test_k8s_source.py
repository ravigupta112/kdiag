from __future__ import annotations

import asyncio
from types import SimpleNamespace as NS

import aiohttp
import pytest
from kubernetes_asyncio import client

from conftest import NOW, run
from fakek8s import (
    FakeApi,
    cstatus,
    deployment,
    meta,
    replicaset,
    v1event,
    v1pod,
)
from kdiag import DiagnosisInput, SourceError, Target, WorkloadRef, diagnose
from kdiag.k8s.ratelimit import TokenBucket
from kdiag.k8s.source import KubernetesSource, map_exception
from kdiag.observability import InMemoryMetrics

REF = WorkloadRef(kind="Deployment", name="shop-web", namespace="shop")
WAIT = ("ImagePullBackOff", 'Failed to pull image "r.io/a:1": manifest unknown')


def make(api: FakeApi, **kw) -> KubernetesSource:
    return KubernetesSource(api.apis(), **kw)


def base_api(**extra) -> FakeApi:
    objs = {"deployments": [deployment()], "replicasets": [replicaset("rs-1")],
            "pods": [v1pod("web-1", owner_uid="rs-rs-1")]} | extra
    return FakeApi(**objs)


def test_never_issues_a_write_or_secret_read_end_to_end() -> None:
    api = base_api(
        pods=[v1pod("web-1", owner_uid="rs-rs-1", containers=[cstatus(False, 0, WAIT)], claims=("data",),
                    env_secret="hunter2-canary-value")],
        events=[v1event("Pod", "web-1", "Failed", 'Failed to pull image "r.io/a:1": manifest unknown')],
        nodes=[], pvcs=[NS(metadata=meta("data"), spec=NS(storage_class_name="fast"), status=NS(phase="Bound"))],
        services=[], slices=[])
    inp = DiagnosisInput(mode="cluster", target=Target(name="shop-web", namespace="shop"))
    r = run(diagnose(inp, make(api), now=NOW))
    assert r.primary and r.primary.rule_id == "IMG-001"
    assert api.calls and all(c.startswith(("read_", "list_")) for c in api.calls)
    assert not any("secret" in c for c in api.calls)
    assert "hunter2" not in r.model_dump_json()


def test_owner_chain_selector_and_name_prefix_fallbacks_are_flagged() -> None:
    owned = v1pod("web-1", owner_uid="rs-rs-1")
    stranger = v1pod("web-2", owner_uid=None)  # matches selector, owned by nothing
    pods = run(make(FakeApi(deployments=[deployment()], replicasets=[replicaset("rs-1")],
                            pods=[owned, stranger])).list_pods(REF, 50))
    assert [(p.name, p.matched_by) for p in pods] == [("web-1", "owner")]
    only_stranger = run(make(FakeApi(deployments=[deployment()], replicasets=[replicaset("rs-1")],
                                     pods=[stranger])).list_pods(REF, 50))
    assert [(p.name, p.matched_by) for p in only_stranger] == [("web-2", "selector")]
    unlabelled = v1pod("shop-web-abc", owner_uid=None, labels={"x": "y"})
    prefix = run(make(FakeApi(deployments=[deployment()], pods=[unlabelled])).list_pods(REF, 50))
    assert [(p.name, p.matched_by) for p in prefix] == [("shop-web-abc", "name")]


def test_pods_of_other_deployments_are_not_included() -> None:
    other = v1pod("other-1", owner_uid="rs-other")
    api = FakeApi(deployments=[deployment()], replicasets=[replicaset("rs-1"), replicaset("rs-2", owner_uid="dep-9")],
                  pods=[v1pod("web-1", owner_uid="rs-rs-1"), other])
    assert [p.name for p in run(make(api).list_pods(REF, 50))] == ["web-1"]


def test_pagination_follows_continue_tokens_and_honours_limit() -> None:
    pods = [v1pod(f"web-{i:04}", owner_uid="rs-rs-1") for i in range(1200)]
    api = FakeApi(deployments=[deployment()], replicasets=[replicaset("rs-1")], pods=pods)
    got = run(make(api).list_pods(REF, 700))
    assert len(got) == 700
    pod_calls = [kw for op, kw in api.call_kwargs if op == "list_namespaced_pod"]
    assert len(pod_calls) == 2 and pod_calls[1]["cont"] == "500" and pod_calls[0]["limit"] == 500


def test_find_workloads_across_namespaces_and_not_found() -> None:
    dep_b = deployment(ns="staging", uid="dep-2")
    api = FakeApi(deployments=[deployment(), dep_b], namespaces=["shop", "staging", "empty"])
    refs = run(make(api).find_workloads(Target(name="shop-web")))
    assert [r.namespace for r in refs] == ["shop", "staging"]
    assert run(make(api).find_workloads(Target(name="nope", namespace="shop"))) == []


def test_namespace_listing_forbidden_when_namespace_not_given() -> None:
    api = FakeApi(deployments=[deployment()])
    api.errors["list_namespace"] = client.ApiException(status=403)
    with pytest.raises(SourceError) as ei:
        run(make(api).find_workloads(Target(name="shop-web")))
    assert ei.value.reason == "forbidden"


def test_allowed_namespaces_are_enforced_before_any_api_call() -> None:
    api = FakeApi(deployments=[deployment(ns="secret-team", uid="d9")])
    src = make(api, allowed_namespaces=frozenset({"shop"}))
    with pytest.raises(SourceError) as ei:
        run(src.find_workloads(Target(name="shop-web", namespace="secret-team")))
    assert ei.value.reason == "forbidden" and api.calls == []
    run(src.find_workloads(Target(name="shop-web")))  # unscoped search only visits allowed namespaces
    assert api.calls == ["read_namespaced_deployment"]


@pytest.mark.parametrize(("status", "reason", "retryable"), [
    (401, "forbidden", False), (403, "forbidden", False), (404, "not_found", False),
    (429, "rate_limited", True), (500, "error", True), (503, "error", True), (409, "error", False),
])
def test_error_mapping_and_no_text_leak(status: int, reason: str, retryable: bool) -> None:
    exc = client.ApiException(status=status, reason="Bearer SECRETTOKEN123 leaked in reason")
    mapped = map_exception(exc)
    assert (mapped.reason, mapped.retryable) == (reason, retryable)
    assert "SECRET" not in (mapped.detail or "")


def test_network_errors_map_to_unreachable() -> None:
    for exc in (aiohttp.ClientConnectionError("boom token=abc"), ConnectionResetError(), OSError("x")):
        assert map_exception(exc).reason == "unreachable"
    assert map_exception(ValueError("password=abc")).detail == "unexpected error"


def test_429_with_retry_after_is_retried_once_then_succeeds() -> None:
    exc = client.ApiException(status=429)
    exc.headers = {"Retry-After": "1"}
    api = base_api()
    api.errors["read_namespaced_deployment"] = [exc]
    slept: list[float] = []

    async def fake_sleep(s: float) -> None:
        slept.append(s)

    run(make(api, sleep=fake_sleep).get_workload_status(REF))
    assert slept == [1.0] and api.calls.count("read_namespaced_deployment") == 2


def test_429_without_hint_or_twice_raises_rate_limited() -> None:
    api = base_api()
    api.errors["read_namespaced_deployment"] = client.ApiException(status=429)
    with pytest.raises(SourceError) as ei:
        run(make(api).get_workload_status(REF))
    assert ei.value.reason == "rate_limited" and ei.value.retryable


def test_events_are_filtered_to_related_objects_and_time_is_never_invented() -> None:
    api = base_api(events=[
        v1event("Pod", "web-1", "Failed", "mine", last="2026-11-21T10:05:00"),
        v1event("Pod", "unrelated-pod", "Failed", "not mine"),
        v1event("ReplicaSet", "rs-1", "FailedCreate", "mine too"),
        v1event("Node", "web-1", "X", "wrong kind"),
    ])
    src = make(api)
    run(src.list_pods(REF, 50))  # learns replica set names
    evs = run(src.list_events(REF, ["web-1"], 100))
    assert sorted(e.message for e in evs) == ["mine", "mine too"]
    assert {e.message: e.timestamp is None for e in evs} == {"mine": False, "mine too": True}


def test_logs_tail_previous_and_400_means_not_found() -> None:
    api = base_api(logs={("web-1", True): "\n".join(f"line {i}" for i in range(50))})
    src = make(api)
    lg = run(src.get_logs(REF, "web-1", "web", True, 5, 1000))
    assert lg.previous and lg.lines[-1] == "line 49" and len(lg.lines) == 5
    with pytest.raises(SourceError) as ei:
        run(src.get_logs(REF, "web-1", "web", False, 5, 1000))
    assert ei.value.reason == "not_found"


def test_services_related_selection_and_nil_ready_counts_as_ready() -> None:
    def svc(name, selector, labels=None):
        return NS(metadata=meta(name, labels=labels), spec=NS(selector=selector))

    def sl(svc_name, readies):
        eps = [NS(conditions=NS(ready=r)) for r in readies]
        return NS(metadata=meta(f"{svc_name}-x", labels={"kubernetes.io/service-name": svc_name}), endpoints=eps)

    api = base_api(
        services=[svc("shop-web", {"app": "web"}), svc("db", {"app": "db"}), svc("wrong", {"app": "web", "tier": "x"}),
                  svc("viahelm", {"app": "zzz"}, labels={"app.kubernetes.io/instance": "rel"})],
        slices=[sl("shop-web", [None, True, False]), sl("viahelm", [])])
    pod = (await_pods := run(make(api).list_pods(REF, 5)))[0].model_copy(
        update={"labels": {"app": "web", "app.kubernetes.io/instance": "rel"}})
    got = {s.name: s for s in run(make(api).list_services(REF, [pod]))}
    assert set(got) == {"shop-web", "wrong", "viahelm"} and await_pods
    assert (got["shop-web"].ready_endpoints, got["shop-web"].not_ready_endpoints) == (2, 1)
    assert got["shop-web"].related_by == "name" and got["viahelm"].related_by == "label"
    assert got["wrong"].related_by == "selector" and got["viahelm"].ready_endpoints == 0


def test_job_and_cronjob_resolution_uses_owner_chain() -> None:
    def job(name, owner="cj-1", created="2026-11-21T10:0", uid=None):
        return NS(metadata=client.V1ObjectMeta(
            name=name, namespace="shop", uid=uid or f"u-{name}", owner_references=[
                client.V1OwnerReference(api_version="v1", kind="CronJob", name="c", uid=owner)],
            creation_timestamp=created + name[-1]),
            status=NS(active=0, failed=1, succeeded=0, conditions=[
                NS(type="Failed", status="True", reason="BackoffLimitExceeded", message=None)]))

    cron = NS(metadata=meta("nightly", uid="cj-1"), spec=NS(), status=NS())
    jobs = [job(f"nightly-{i}") for i in range(5)] + [job("other-1", owner="cj-2")]
    pods = [v1pod("p-4", owner_uid="u-nightly-4", labels={"job-name": "nightly-4"}),
            v1pod("p-0", owner_uid="u-nightly-0", labels={"job-name": "nightly-0"})]
    api = FakeApi(cronjobs=[cron], jobs=jobs, pods=pods)
    cref = WorkloadRef(kind="CronJob", name="nightly", namespace="shop")
    src = make(api)
    assert [j.name for j in run(src.list_jobs(cref))] == ["nightly-4", "nightly-3", "nightly-2"]
    assert [p.name for p in run(src.list_pods(cref, 50))] == ["p-4"]  # only the newest 3 jobs are read


def test_rate_limiter_is_applied_to_every_call_and_metrics_and_audit_recorded() -> None:
    api = base_api()
    acquired: list[int] = []

    class CountingBucket(TokenBucket):
        async def acquire(self) -> None:
            acquired.append(1)

    class Audit:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, str]]] = []

        def record(self, event: str, **fields: str) -> None:
            self.events.append((event, fields))

    m, audit = InMemoryMetrics(), Audit()
    src = make(api, limiter=CountingBucket(100, 10), metrics=m, audit=audit)
    run(src.list_pods(REF, 50))
    assert len(acquired) == len(api.calls) > 1
    assert m.count("kdiag_k8s_api_calls_total") == len(api.calls)
    assert all(e == "k8s.read" and f["namespace"] == "shop" for e, f in audit.events)


def test_token_bucket_throttles() -> None:
    async def go() -> float:
        b = TokenBucket(rate_per_s=50, burst=1)
        t0 = asyncio.get_running_loop().time()
        for _ in range(4):
            await b.acquire()
        return asyncio.get_running_loop().time() - t0

    assert run(go()) >= 0.05
    with pytest.raises(ValueError):
        TokenBucket(0, 1)


def test_nodes_and_pvcs_skip_missing_but_surface_total_failure() -> None:
    api = base_api(nodes=[NS(metadata=meta("node-1"), status=NS(conditions=[
        NS(type="Ready", status="False", reason=None, message=None)]))])
    nodes = run(make(api).get_nodes(["node-1", "ghost"]))
    assert [n.name for n in nodes] == ["node-1"]
    api.errors["read_node"] = client.ApiException(status=403)
    with pytest.raises(SourceError) as ei:
        run(make(api).get_nodes(["node-1"]))
    assert ei.value.reason == "forbidden"


def real_ca_pem() -> str:
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/k",
                        "-out", f"{d}/c", "-days", "1", "-subj", "/CN=test-ca"], check=True,
                       capture_output=True)
        return open(f"{d}/c").read()


def test_connect_builds_verified_tls_config_and_cleans_up_ca_file() -> None:
    import os

    from kdiag.k8s.kubeconfig import ClusterCredentials

    seen: dict[str, object] = {}

    async def go() -> None:
        creds = ClusterCredentials("https://k8s.example.com:6443", "tok123", real_ca_pem())
        async with KubernetesSource.connect(creds) as src:
            cfg = src._a.core.api_client.configuration
            seen.update(host=cfg.host, verify=cfg.verify_ssl, ca=cfg.ssl_ca_cert, key=dict(cfg.api_key),
                        prefix=dict(cfg.api_key_prefix), ca_exists=os.path.exists(cfg.ssl_ca_cert))

    run(go())
    assert seen["host"] == "https://k8s.example.com:6443" and seen["verify"] is True
    assert seen["key"] == {"BearerToken": "tok123"} and seen["prefix"] == {"BearerToken": "Bearer"}
    assert seen["ca_exists"] is True and not os.path.exists(str(seen["ca"]))
