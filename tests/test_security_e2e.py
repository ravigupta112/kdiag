"""End-to-end secret sweep: plant canaries in every input channel, run the whole stack (API, rules,
cache, history, export), then search every place output can land."""
from __future__ import annotations

import json
import logging
import pathlib
import re
import subprocess
import sys

from conftest import ctr, pod, run
from kdiag import (
    Condition,
    ContainerLog,
    JobEvidence,
    NodeEvidence,
    ServiceEvidence,
    WorkloadStatus,
    render_text,
)
from kdiag.models import DiagnosisReport
from kdiag.service import ServiceSettings
from svc_helpers import client, hdr, make_env

ROOT = pathlib.Path(__file__).parent.parent
CANARIES = ["hunter2-canary", "canarytoken1234567890", "canary-sched", "canary-helm", "canary-node",
            "canary-job", "canary-wl", "canary-log", "canary-evt", "canary-label", "canary-term"]


def dump(m) -> dict:
    return m.model_dump(mode="json")


def build_body() -> dict:
    c = ctr(waiting_reason="ImagePullBackOff",
            waiting_message='Failed to pull image "r.io/a:1": unauthorized password=hunter2-canary '
                            "Authorization: Bearer canarytoken1234567890",
            terminated_message="boom api_key=canary-term")
    crash = ctr(name="api", waiting_reason="CrashLoopBackOff", last_exit_code=1, restart_count=2)
    pods = [
        pod("web-1", "Pending", containers=[c], conditions=[Condition(
            type="PodScheduled", status="False", reason="Unschedulable",
            message="0/3 nodes are available: 3 Insufficient cpu. token=canary-sched")]).model_copy(
                update={"labels": {"app": "web"}, "message": "secret=canary-evt"}),
        pod("web-2", containers=[crash]).model_copy(update={"labels": {"app": "web"}}),
    ]
    return {
        "mode": "evidence", "save": True, "job_id": "sweep-1",
        "pods": [dump(p) for p in pods],
        "events": [{"object_kind": "Pod", "object_name": "web-1", "type": "Warning", "reason": "Failed",
                    "message": "Error: secret \"db\" not found token=canary-evt", "timestamp": "2026-11-21T10:00:00Z"}],
        "nodes": [dump(NodeEvidence(name="n1", conditions=(Condition(type="Ready", status="False",
                                                                     message="password=canary-node"),)))],
        "jobs": [dump(JobEvidence(name="j", namespace="shop", conditions=(Condition(
            type="Failed", status="True", reason="DeadlineExceeded", message="token=canary-job"),)))],
        "services": [dump(ServiceEvidence(name="web", namespace="shop", selector={"app": "other",
                                                                                   "x": "password=canary-label"}))],
        "workload_status": dump(WorkloadStatus(generation=2, observed_generation=2, replicas=2, updated_replicas=0,
                                               ready_replicas=2, available_replicas=2, conditions=(
            Condition(type="ReplicaFailure", status="True", reason="FailedCreate",
                      message="forbidden: exceeded quota: q token=canary-wl"),))),
        "logs": [dump(ContainerLog(pod="web-2", container="api", previous=True, lines=(
            "ModuleNotFoundError: No module named 'fastapi'", "password=canary-log")))],
        "helm_output": "Error: UPGRADE FAILED: another operation (upgrade) is in progress api_key=canary-helm",
        "job_log": "deploy step\nAuthorization: Bearer canarytoken1234567890\n",
        "export": {"acknowledge_external_sharing": True},
    }


def test_no_canary_survives_anywhere(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    env = make_env(ServiceSettings(rate_per_s=10_000, rate_burst=10_000))
    admin = hdr("tok-a-admin")
    seen: list[str] = []

    async def go() -> None:
        async with client(env) as c:
            r = await c.post("/v1/diagnose", json=build_body(), headers=admin)
            assert r.status_code == 200, r.text
            seen.append(r.text)
            body = r.json()
            assert body["report"]["primary"] is not None and body["prompt"]["text"]
            rid = body["meta"]["report_id"]
            seen.append((await c.get(f"/v1/reports/{rid}", headers=admin)).text)
            seen.append((await c.get("/v1/reports?cluster_id=prod&name=x", headers=admin)).text)
            ex = await c.post(f"/v1/reports/{rid}/export", json={"acknowledge_external_sharing": True}, headers=admin)
            assert ex.status_code == 200
            seen.append(ex.text)
            rep = DiagnosisReport.model_validate(body["report"])
            seen.append(render_text(rep))

    run(go())
    seen.append(json.dumps([list(r) for r in env.store._conn.execute("SELECT body, history FROM reports")]))
    seen.append(json.dumps(env.audit.events))
    seen.append(json.dumps([[str(k), v] for k, v in env.metrics.counters.items()]))
    seen.append(json.dumps({k: v for k, v in env.metrics.observations.items()}))
    seen.append(caplog.text)
    blob = "\n".join(seen).lower()
    leaked = [c for c in CANARIES if c in blob]
    assert leaked == [], leaked
    assert "fastapi" in blob  # the useful, non-secret signal still comes through


def test_only_restricted_names_are_reflected_from_logs() -> None:
    env = make_env(ServiceSettings(rate_per_s=10_000, rate_burst=10_000))

    async def go():
        async with client(env) as c:
            body = {"mode": "evidence", "pods": [dump(pod("p"))], "logs": [dump(ContainerLog(
                pod="p", container="web", previous=True, lines=(
                    "ModuleNotFoundError: No module named 'a b <script>alert(1)</script>'",
                    "Traceback ... SECRET-LOG-LINE-CONTENT")))]}
            return await c.post("/v1/diagnose", json=body, headers=hdr("tok-a"))

    r = run(go())
    assert "SECRET-LOG-LINE-CONTENT" not in r.text and "<script>" not in r.text


# ---- structural guarantees ------------------------------------------------------------------------

def test_adapter_only_uses_read_operations_and_never_secret_or_exec_apis() -> None:
    src = (ROOT / "src" / "kdiag" / "k8s" / "source.py").read_text()
    ops = set(re.findall(r'"((?:read|list|create|patch|delete|replace|connect|get|watch)_[a-z_]+)"', src))
    assert ops, "expected to find API operation names"
    assert all(o.startswith(("read_", "list_")) for o in ops), sorted(o for o in ops if not o.startswith(("read_", "list_")))
    forbidden = re.compile(r"secret|exec|attach|portforward|proxy|token_review|selfsubject|impersonat", re.IGNORECASE)
    assert not [o for o in ops if forbidden.search(o)]
    assert "kubectl" not in src and "subprocess" not in src


def test_the_whole_source_tree_is_free_of_command_execution() -> None:
    bad = re.compile(r"\b(subprocess|shlex|pty|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*|asyncio\.create_subprocess\w*)\b")
    offenders = [str(p.relative_to(ROOT)) for p in (ROOT / "src").rglob("*.py") if bad.search(p.read_text())]
    assert offenders == []


def test_no_llm_or_ai_client_is_imported_by_the_library() -> None:
    bad = re.compile(r"^\s*(?:import|from)\s+(openai|anthropic|langchain|transformers|litellm|google\.generativeai)\b", re.MULTILINE)
    assert [p.name for p in (ROOT / "src").rglob("*.py") if bad.search(p.read_text())] == []


def test_core_import_stays_light_and_optional_dependencies_stay_optional() -> None:
    code = ("import sys, kdiag; "
            "bad=[m for m in ('kubernetes_asyncio','fastapi','yaml','starlette','prometheus_client','aiohttp') if m in sys.modules]; "
            "print(bad)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"}).stdout.strip()
    assert out == "[]"


def test_declared_runtime_dependencies_are_minimal() -> None:
    import tomllib
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert [d.split(">")[0] for d in meta["dependencies"]] == ["pydantic"]
    assert {"k8s", "service", "metrics", "dev"} <= set(meta["optional-dependencies"])
