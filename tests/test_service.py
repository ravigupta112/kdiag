from __future__ import annotations

import json
from contextlib import asynccontextmanager

from conftest import run
from kdiag import SourceError
from kdiag.service import ServiceSettings, TTLCache, cache_key
from kdiag.testing import FakeSource
from svc_helpers import (
    CANARY_LOG,
    CLUSTER,
    EVIDENCE,
    TOKENS,
    client,
    hdr,
    kubeconfig_text,
    make_env,
)


def call(env, method, path, token="tok-a", **kw):
    async def go():
        async with client(env) as c:
            return await c.request(method, path, headers=hdr(token) | kw.pop("headers", {}), **kw)
    return run(go())


def post(env, body, token="tok-a", **kw):
    return call(env, "POST", "/v1/diagnose", token, json=body, **kw)


# ---- authentication / envelope / flag -------------------------------------------------------------

def test_unauthenticated_requests_get_401_and_no_detail() -> None:
    env = make_env()
    for tok in (None, "wrong"):
        r = post(env, EVIDENCE, token=tok)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
        assert r.json()["error"]["code"] == "unauthenticated" and r.json()["report"] is None
    assert call(env, "GET", "/healthz", None).json() == {"ok": True}


def test_envelope_and_request_id() -> None:
    r = post(make_env(), EVIDENCE)
    body = r.json()
    assert r.status_code == 200 and set(body) >= {"report", "error", "meta"}
    assert body["report"]["primary"]["rule_id"] == "HLM-003" and body["error"] is None
    assert r.headers["x-request-id"] == body["meta"]["request_id"]


def test_feature_flag_off_returns_404_everywhere_before_auth() -> None:
    env = make_env(ServiceSettings(enabled=False))
    for method, path in (("POST", "/v1/diagnose"), ("GET", "/v1/reports/x"), ("GET", "/v1/reports?cluster_id=a&name=b")):
        r = call(env, method, path, None, json=EVIDENCE if method == "POST" else None)
        assert r.status_code == 404 and r.json()["error"]["code"] == "disabled"


def test_shadow_mode_runs_but_returns_no_report() -> None:
    env = make_env(ServiceSettings(shadow_mode=True, rate_per_s=1000, rate_burst=1000))
    r = post(env, CLUSTER)
    assert r.status_code == 202 and r.json()["report"] is None and r.json()["meta"]["shadow"] is True
    assert env.metrics.count("kdiag_diagnosis_total", mode="cluster") == 1


# ---- tenant isolation and authorization -----------------------------------------------------------

def test_tenants_only_ever_see_their_own_cluster_data() -> None:
    env = make_env()
    a = post(env, CLUSTER, "tok-a").json()["report"]["primary"]["rule_id"]
    b = post(env, CLUSTER, "tok-b").json()["report"]["primary"]["rule_id"]
    assert (a, b) == ("IMG-001", "POD-004")  # same cluster id "prod", different tenants, different data


def test_cluster_without_grant_is_403_and_granted_but_unregistered_is_404() -> None:
    env = make_env()
    assert post(env, CLUSTER | {"cluster_id": "ghost"}).status_code == 403
    assert post(env, CLUSTER | {"cluster_id": "nofactory"}).status_code == 404
    assert post(env, CLUSTER | {"cluster_id": "nofactory"}).json()["error"]["code"] == "cluster_not_found"


def test_namespace_scoped_grant_is_enforced_server_side() -> None:
    env = make_env()
    ok = post(env, CLUSTER | {"cluster_id": "restricted"})
    assert ok.status_code == 200
    denied = post(env, {"mode": "cluster", "cluster_id": "restricted",
                        "target": {"name": "shop-web", "namespace": "secret-team"}})
    assert denied.status_code == 403 and env.sources[("tenantA", "restricted")].calls.count("find_workloads") == 1


def test_container_logs_require_debug_authorization() -> None:
    env = make_env()
    r = post(env, CLUSTER | {"include_logs": True}, "tok-a")
    assert r.status_code == 403 and r.json()["error"]["code"] == "debug_not_permitted"
    assert "get_logs" not in env.sources[("tenantA", "prod")].calls
    ok = post(env, CLUSTER | {"include_logs": True}, "tok-a-debug")
    assert ok.status_code == 200
    rules = {f["rule_id"] for f in [ok.json()["report"]["primary"], *ok.json()["report"]["supporting"]]}
    assert "APP-001" in rules
    assert "hunter2" not in ok.text and "fastapi" in ok.text and CANARY_LOG not in ok.text  # name only, no raw line


# ---- validation -----------------------------------------------------------------------------------

def test_clients_cannot_set_limits_tenant_or_unknown_fields() -> None:
    env = make_env()
    for extra in ({"limits": {"max_pods": 200}}, {"tenant_id": "tenantB"}, {"collect_logs": True}):
        r = post(env, EVIDENCE | extra)
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"


def test_validation_errors_never_echo_input_values() -> None:
    env = make_env()
    bad = [{"mode": "cluster", "cluster_id": "prod", "target": {"name": "Hunter2_Canary-Value"}},
           {"mode": "evidence", "helm_output": 12345, "password": "hunter2-canary"},
           {"mode": "evidence", "pods": [{"name": "x" * 300, "namespace": "hunter2-canary"}]}]
    for body in bad:
        r = post(env, body)
        assert r.status_code == 422 and "hunter2" not in r.text.lower() and "canary" not in r.text.lower()
        assert all(set(d) == {"loc", "msg", "type"} for d in r.json()["details"])


def test_cluster_mode_requires_a_cluster_or_kubeconfig_and_target() -> None:
    env = make_env()
    assert post(env, {"mode": "cluster", "target": {"name": "x"}}).status_code == 422
    assert post(env, {"mode": "cluster", "cluster_id": "prod"}).status_code == 422


def test_oversized_body_is_rejected_early() -> None:
    env = make_env(ServiceSettings(max_body_bytes=500, rate_per_s=1000, rate_burst=1000))
    r = post(env, EVIDENCE | {"job_log": "x" * 2000})
    assert r.status_code == 413 and r.json()["error"]["code"] == "too_large"


# ---- rate limit / backpressure --------------------------------------------------------------------

def test_rate_limit_is_per_principal_with_retry_after() -> None:
    env = make_env(ServiceSettings(rate_per_s=0.1, rate_burst=2))
    codes = [post(env, EVIDENCE, "tok-a").status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]
    limited = post(env, EVIDENCE, "tok-a")
    assert int(limited.headers["retry-after"]) >= 1
    assert post(env, EVIDENCE, "tok-a2").status_code == 200  # another user of the same tenant is unaffected
    assert env.metrics.count("kdiag_rate_limited_total") >= 2


def test_backpressure_returns_503_when_saturated() -> None:
    env = make_env(ServiceSettings(max_concurrent=1, queue_wait_s=0.05, rate_per_s=1000, rate_burst=1000),
                   a_delay=0.4)
    from svc_helpers import run_all

    async def one(name: str):
        async with client(env) as c:
            body = CLUSTER | {"job_id": name, "refresh": True}
            return await c.post("/v1/diagnose", json=body, headers=hdr("tok-a"))

    first, second = run_all(one("j1"), one("j2"))
    codes = sorted([first.status_code, second.status_code])
    assert codes == [200, 503]
    busy = first if first.status_code == 503 else second
    assert busy.headers["retry-after"] == "2" and env.metrics.count("kdiag_backpressure_total") == 1


# ---- cache ----------------------------------------------------------------------------------------

def test_cache_hit_refresh_ttl_and_tenant_separation() -> None:
    env = make_env(ServiceSettings(cache_ttl_s=30, rate_per_s=1000, rate_burst=1000))
    src = env.sources[("tenantA", "prod")]
    first = post(env, CLUSTER).json()["meta"]["cached"]
    second = post(env, CLUSTER).json()["meta"]["cached"]
    assert (first, second) == (False, True) and src.calls.count("find_workloads") == 1
    assert post(env, CLUSTER | {"refresh": True}).json()["meta"]["cached"] is False
    assert src.calls.count("find_workloads") == 2
    env.clock[0] += 31  # past the TTL
    assert post(env, CLUSTER).json()["meta"]["cached"] is False
    assert post(env, CLUSTER, "tok-b").json()["report"]["primary"]["rule_id"] == "POD-004"  # not tenant A's entry
    assert env.metrics.count("kdiag_cache_total", result="hit") == 1


def test_identical_concurrent_requests_share_one_diagnosis() -> None:
    env = make_env(a_delay=0.2)
    from svc_helpers import run_all

    async def one():
        async with client(env) as c:
            return await c.post("/v1/diagnose", json=CLUSTER, headers=hdr("tok-a"))

    rs = run_all(*[one() for _ in range(6)])
    assert all(r.status_code == 200 for r in rs)
    assert env.sources[("tenantA", "prod")].calls.count("find_workloads") == 1
    assert sorted(str(r.json()["meta"]["cached"]) for r in rs).count("coalesced") == 5


def test_failure_in_a_shared_diagnosis_does_not_wedge_later_requests() -> None:
    env = make_env(a_delay=0.1)
    src = env.sources[("tenantA", "prod")]
    src.fail["list_pods"] = SourceError("forbidden")
    r1 = post(env, CLUSTER)
    assert r1.status_code == 200 and r1.json()["report"]["status"] == "partial"
    del src.fail["list_pods"]
    assert post(env, CLUSTER | {"refresh": True}).json()["report"]["status"] == "diagnosed"


def test_cache_unit_lru_bytes_and_invalidate() -> None:
    from conftest import NOW
    from kdiag import DiagnosisInput, diagnose
    rep = run(diagnose(DiagnosisInput(mode="evidence", helm_output="Error: release: not found"), now=NOW))
    t = [0.0]
    c = TTLCache(max_entries=2, ttl_s=10, clock=lambda: t[0])
    k = [cache_key("t", "c", "ns", "Deployment", f"n{i}", None, False) for i in range(3)]
    c.set(k[0], rep); c.set(k[1], rep); c.get(k[0]); c.set(k[2], rep)
    assert c.get(k[1]) is None and c.get(k[0]) and len(c) == 2  # LRU evicted the untouched one
    assert c.invalidate(lambda key: key[4] == "n0") == 1 and c.get(k[0]) is None
    t[0] = 11
    assert c.get(k[2]) is None and len(c) == 0 and c.size_bytes == 0
    tiny = TTLCache(max_entries=10, ttl_s=10, max_bytes=10)
    tiny.set(k[0], rep)
    assert len(tiny) == 0  # an oversize entry is never cached
    assert cache_key("t", "c", None, "Deployment", "n", None, False, "all") != cache_key("t", "c", None, "Deployment", "n", None, False, "ab12")
    assert cache_key("t1", "c", "n", "Deployment", "x", None, False)[0] == "t1"


# ---- status mapping -------------------------------------------------------------------------------

def test_http_status_follows_report_status() -> None:
    env = make_env()
    r = post(env, CLUSTER | {"target": {"name": "ghost", "namespace": "shop"}})
    assert r.status_code == 404 and r.json()["error"]["code"] == "target_not_found" and r.json()["report"]
    env.sources[("tenantA", "prod")].fail["find_workloads"] = SourceError("unreachable", retryable=True)
    r = post(env, CLUSTER | {"refresh": True})
    assert r.status_code == 502 and r.json()["error"]["code"] == "cluster_unreachable"
    env.sources[("tenantA", "prod")].fail["find_workloads"] = SourceError("timeout", retryable=True)
    assert post(env, CLUSTER | {"refresh": True}).status_code == 504
    assert post(env, EVIDENCE).status_code == 200


def test_unhandled_errors_are_generic_and_leak_nothing() -> None:
    env = make_env()

    class Boom(FakeSource):
        async def find_workloads(self, target):
            raise RuntimeError("password=hunter2-canary token=abc")

    from kdiag.service import InMemoryRegistry
    env.app.router.routes  # noqa: B018
    import svc_helpers as h
    from kdiag.service import Deps, GrantAuthorizer, StaticAuthenticator, create_app
    app = create_app(Deps(settings=ServiceSettings(rate_per_s=1000, rate_burst=1000),
                          authenticator=StaticAuthenticator(TOKENS), authorizer=GrantAuthorizer(h.GRANTS),
                          registry=InMemoryRegistry({("tenantA", "prod"): lambda a: Boom([])})))
    env.app = app
    r = post(env, CLUSTER)
    # the collector swallows source errors into partial reads; a registry failure becomes a 500
    assert r.status_code == 200 and "hunter2" not in r.text

    class BadRegistry:
        @asynccontextmanager
        async def open(self, *a):
            raise RuntimeError("password=hunter2-canary")
            yield

    env.app = create_app(Deps(settings=ServiceSettings(rate_per_s=1000, rate_burst=1000),
                              authenticator=StaticAuthenticator(TOKENS), authorizer=GrantAuthorizer(h.GRANTS),
                              registry=BadRegistry()))
    r = post(env, CLUSTER)
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal" and "hunter2" not in r.text


# ---- history --------------------------------------------------------------------------------------

def test_save_get_list_and_isolation() -> None:
    env = make_env()
    saved = post(env, CLUSTER | {"save": True, "job_id": "job-1"}).json()["meta"]
    rid = saved["report_id"]
    assert saved["saved"] is True and rid
    got = call(env, "GET", f"/v1/reports/{rid}")
    assert got.status_code == 200 and got.json()["report"]["primary"]["rule_id"] == "IMG-001"
    assert call(env, "GET", f"/v1/reports/{rid}", "tok-b").status_code == 404  # other tenant
    assert call(env, "GET", f"/v1/reports/{rid}", None).status_code == 401
    assert call(env, "GET", "/v1/reports/nope").status_code == 404
    lst = call(env, "GET", "/v1/reports?cluster_id=prod&name=shop-web&namespace=shop")
    assert lst.status_code == 200 and [x["id"] for x in lst.json()["reports"]] == [rid]
    assert call(env, "GET", "/v1/reports?cluster_id=ghost&name=shop-web").status_code == 403
    assert call(env, "GET", "/v1/reports?cluster_id=prod&name=shop-web", "tok-b").json()["reports"] == []


def test_merge_by_job_and_unreadable_history_entries() -> None:
    env = make_env()
    a = post(env, CLUSTER | {"save": True, "job_id": "j"}).json()["meta"]
    b = post(env, CLUSTER | {"save": True, "job_id": "j", "refresh": True}).json()["meta"]
    assert a["report_id"] == b["report_id"] and b["save_action"] == "deduped"
    env.store._conn.execute("UPDATE reports SET body='{corrupt' WHERE id=?", (a["report_id"],))
    r = call(env, "GET", f"/v1/reports/{a['report_id']}")
    assert r.status_code == 200 and r.json()["report"] is None and r.json()["meta"]["unreadable"] == "corrupt"


def test_save_failure_never_fails_the_diagnosis() -> None:
    env = make_env()
    env.store._conn.execute("DROP TABLE reports")
    r = post(env, CLUSTER | {"save": True})
    assert r.status_code == 200 and r.json()["meta"]["saved"] is False and "save_error" in r.json()["meta"]


# ---- export ---------------------------------------------------------------------------------------

def test_export_requires_consent_before_any_cluster_read_and_a_role() -> None:
    env = make_env()
    src = env.sources[("tenantA", "prod")]
    r = post(env, CLUSTER | {"export": {}}, "tok-a-admin")
    assert r.status_code == 400 and r.json()["error"]["code"] == "consent_required" and src.calls == []
    assert post(env, CLUSTER | {"export": {"acknowledge_external_sharing": True}}, "tok-a").status_code == 403
    ok = post(env, CLUSTER | {"export": {"acknowledge_external_sharing": True}}, "tok-a-admin")
    assert ok.status_code == 200 and "IMG-001" in ok.json()["prompt"]["text"]
    assert ok.json()["prompt"]["metadata"]["masking_applied"] is True


def test_export_of_a_stored_report() -> None:
    env = make_env()
    rid = post(env, CLUSTER | {"save": True}, "tok-a-admin").json()["meta"]["report_id"]
    path = f"/v1/reports/{rid}/export"
    assert call(env, "POST", path, "tok-a-admin", json={}).status_code == 400
    assert call(env, "POST", path, "tok-a", json={"acknowledge_external_sharing": True}).status_code == 403
    assert call(env, "POST", path, "tok-b", json={"acknowledge_external_sharing": True}).status_code == 404
    ok = call(env, "POST", path, "tok-a-admin", json={"acknowledge_external_sharing": True, "max_chars": 900})
    assert ok.status_code == 200 and ok.json()["prompt"]["metadata"]["chars"] <= 1100
    sha = ok.json()["prompt"]["metadata"]["sha256"]
    exports = [f for e, f in env.audit.events if e == "export"]
    assert exports and exports[-1]["sha256"] == sha and "text" not in exports[-1]
    assert env.metrics.count("kdiag_prompt_exports_total", result="ok") >= 1


# ---- kubeconfig upload ----------------------------------------------------------------------------

def upload_env(**kw):
    opened: list[object] = []

    @asynccontextmanager
    async def fake_open(creds, allowed):
        opened.append(creds)
        from conftest import pull_pod
        from svc_helpers import PULL, REF
        yield FakeSource([REF], pods=[pull_pod(PULL).model_copy(update={"namespace": "shop"})])

    st = ServiceSettings(allow_kubeconfig_upload=True, kubeconfig_allowed_hosts=("*.example.com",),
                         rate_per_s=1000, rate_burst=1000, **kw)
    env = make_env(st, open_credentials=fake_open)
    env.opened = opened
    return env


UPLOAD = {"mode": "cluster", "target": {"name": "shop-web", "namespace": "shop"}}


def test_kubeconfig_upload_is_off_by_default_and_role_gated() -> None:
    env = make_env()
    r = post(env, UPLOAD | {"kubeconfig": kubeconfig_text()}, "tok-a-admin")
    assert r.status_code == 403 and r.json()["error"]["code"] == "upload_not_permitted"
    env = upload_env()
    assert post(env, UPLOAD | {"kubeconfig": kubeconfig_text()}, "tok-a").status_code == 403


def test_kubeconfig_upload_rejections_never_echo_the_token() -> None:
    env = upload_env()
    for extra, code in (({"exec": {"command": "aws"}}, "exec_plugin"), ({"tokenFile": "/x"}, "file_reference")):
        r = post(env, UPLOAD | {"kubeconfig": kubeconfig_text(extra_user=extra)}, "tok-a-admin")
        assert r.status_code == 422 and r.json()["error"]["code"] == code and "CANARYKUBETOKEN" not in r.text
    r = post(env, UPLOAD | {"kubeconfig": kubeconfig_text(server="https://evil.example.org")}, "tok-a-admin")
    assert r.status_code == 422 and r.json()["error"]["code"] == "host_not_allowed"
    assert post(env, UPLOAD | {"kubeconfig": "a: [", "cluster_id": "prod"}, "tok-a-admin").status_code == 422
    assert env.opened == []


def test_kubeconfig_upload_works_and_the_token_is_nowhere_afterwards() -> None:
    env = upload_env()
    r = post(env, UPLOAD | {"kubeconfig": kubeconfig_text(), "save": True, "job_id": "u1"}, "tok-a-admin")
    assert r.status_code == 200 and r.json()["report"]["primary"]["rule_id"] == "IMG-001"
    assert r.json()["meta"]["cached"] is False and len(env.opened) == 1
    again = post(env, UPLOAD | {"kubeconfig": kubeconfig_text()}, "tok-a-admin")
    assert again.json()["meta"]["cached"] is False  # uploads are never cached
    everything = json.dumps({
        "resp": [r.text, again.text], "audit": env.audit.events, "metrics": [str(k) for k in env.metrics.counters],
        "store": [row[0] for row in env.store._conn.execute("SELECT body FROM reports")]})
    assert "CANARYKUBETOKEN" not in everything and "BEGIN CERTIFICATE" not in everything
    assert "CANARYKUBETOKEN" not in repr(env.opened[0])


def test_audit_records_identifiers_only() -> None:
    env = make_env()
    post(env, CLUSTER, "tok-a-debug")
    ev = next(f for e, f in env.audit.events if e == "diagnose")
    assert ev == {"tenant": "tenantA", "user": "dave", "cluster": "prod", "namespace": "shop",
                  "target": "shop-web", "status": "diagnosed", "mode": "cluster"}


def test_adhoc_reports_are_readable_by_their_tenant_only_and_the_label_is_reserved() -> None:
    env = make_env()
    saved = post(env, EVIDENCE | {"save": True, "job_id": "adhoc-1"}).json()["meta"]
    rid = saved["report_id"]
    assert saved["saved"] and call(env, "GET", f"/v1/reports/{rid}").status_code == 200
    assert call(env, "GET", f"/v1/reports/{rid}", "tok-b").status_code == 404
    lst = call(env, "GET", "/v1/reports?cluster_id=adhoc&name=shop-web")
    assert lst.status_code == 200
    assert call(env, "GET", "/v1/reports?cluster_id=adhoc&name=x", "tok-b").json()["reports"] == []
    assert post(env, CLUSTER | {"cluster_id": "adhoc"}).status_code == 422
