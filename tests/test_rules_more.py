"""Positive and negative fixtures for every rule family added after Phase 1."""
from __future__ import annotations

import pytest

from conftest import ctr, pod
from kdiag.models import (
    Condition,
    ContainerLog,
    EventEvidence,
    Evidence,
    JobEvidence,
    NodeEvidence,
    PvcEvidence,
    ServiceEvidence,
    WorkloadStatus,
)
from kdiag.rules.admission import AdmissionRule
from kdiag.rules.applogs import NetworkLogRule, NodeLogRule, PythonLogRule
from kdiag.rules.config import ContainerStartRule, MissingConfigRule
from kdiag.rules.network import CniRule, ServiceEndpointsRule
from kdiag.rules.node import NamespaceTerminatingRule, NodeConditionRule
from kdiag.rules.pod import EvictionRule
from kdiag.rules.probe import ProbeRule
from kdiag.rules.storage import MountFailureRule, PendingPvcRule
from kdiag.rules.workload import JobFailureRule, ProgressDeadlineRule, ReplicaFailureRule


def ev(**kw):
    return Evidence(**kw)


def e(kind="Pod", name="p", reason="Failed", msg="", type_="Warning"):
    return EventEvidence(object_kind=kind, object_name=name, type=type_, reason=reason, message=msg)


def one(rule, evidence):
    out = rule.evaluate(evidence)
    assert len(out) == 1, out
    return out[0]


# --- CFG-001 ---------------------------------------------------------------------------------

@pytest.mark.parametrize(("msg", "sub", "detail"), [
    ('secret "db-creds" not found', "secret_not_found", "db-creds"),
    ('configmap "app-config" not found', "configmap_not_found", "app-config"),
    ("couldn't find key DATABASE_URL in Secret shop/db", "key_missing", "DATABASE_URL"),
    ("something odd about env", "config_error", None),
])
def test_cfg_subcauses(msg: str, sub: str, detail: str | None) -> None:
    p = pod(phase="Pending", containers=[ctr(waiting_reason="CreateContainerConfigError", waiting_message=msg)])
    f = one(MissingConfigRule(), ev(pods=(p,), available=frozenset({"pods"})))
    assert f.sub_cause == sub and f.details.get("detail") == detail


def test_cfg_negative_and_unrelated_failed_events_ignored() -> None:
    p = pod(containers=[ctr(ready=True)])
    unrelated = e(msg="Error: ErrImagePull something")
    assert MissingConfigRule().evaluate(ev(pods=(p,), events=(unrelated,))) == []


# --- POD-002 ---------------------------------------------------------------------------------

@pytest.mark.parametrize(("msg", "sub"), [
    ('exec: "foo": executable file not found in $PATH', "exec_not_found"),
    ("exec /app/run: exec format error", "exec_format"),
    ("open /etc/x: no such file or directory", "no_such_file"),
    ("fork/exec /app: permission denied", "permission_denied"),
    ("OCI runtime create failed: weird", "runtime_error"),
])
def test_start_errors(msg: str, sub: str) -> None:
    p = pod(containers=[ctr(waiting_reason="CreateContainerError", waiting_message=msg)])
    assert one(ContainerStartRule(), ev(pods=(p,))).sub_cause == sub


def test_start_error_from_terminated_state_and_negative() -> None:
    p = pod(containers=[ctr(terminated_reason="StartError", terminated_message="exec format error")])
    assert one(ContainerStartRule(), ev(pods=(p,))).sub_cause == "exec_format"
    assert ContainerStartRule().evaluate(ev(pods=(pod(containers=[ctr(ready=True)]),))) == []


# --- POD-006 / NODE-001 / NS-001 ----------------------------------------------------------------

@pytest.mark.parametrize(("msg", "sub"), [
    ("The node was low on resource: ephemeral-storage. Container web was using 2Gi", "disk"),
    ("The node was low on resource: memory. Threshold quantity: 100Mi", "memory"),
    ("The node was low on resource: pids", "pid"),
    ("Pod was evicted for reasons", "other"),
])
def test_eviction(msg: str, sub: str) -> None:
    p = pod(phase="Failed")
    p = p.model_copy(update={"reason": "Evicted", "message": msg})
    assert one(EvictionRule(), ev(pods=(p,))).sub_cause == sub
    assert EvictionRule().evaluate(ev(pods=(pod(phase="Failed"),))) == []


def test_node_conditions() -> None:
    nodes = (
        NodeEvidence(name="n1", conditions=(Condition(type="Ready", status="Unknown"),)),
        NodeEvidence(name="n2", conditions=(Condition(type="Ready", status="False"),
                                            Condition(type="DiskPressure", status="True"))),
        NodeEvidence(name="n3", conditions=(Condition(type="Ready", status="True"),
                                            Condition(type="MemoryPressure", status="False"))),
    )
    subs = {f.sub_cause: f.evidence_refs for f in NodeConditionRule().evaluate(ev(nodes=nodes))}
    assert subs == {"not_ready_unknown": ("node/n1",), "not_ready": ("node/n2",),
                    "disk_pressure": ("node/n2",)}


def test_namespace_terminating() -> None:
    assert one(NamespaceTerminatingRule(), ev(namespace_phase="Terminating")).sub_cause == "terminating"
    assert NamespaceTerminatingRule().evaluate(ev(namespace_phase="Active")) == []


# --- ADM-001 ---------------------------------------------------------------------------------

@pytest.mark.parametrize(("kind", "msg", "sub", "detail"), [
    ("ReplicaSet", 'Error creating: pods "x" is forbidden: exceeded quota: team-quota, requested: cpu=1, used: cpu=2, limited: cpu=2',
     "quota", "team-quota"),
    ("ReplicaSet", "pods is forbidden: minimum memory usage per Container is 64Mi, but request is 32Mi",
     "limit_range", "minimum memory usage per Container"),
    ("ReplicaSet", 'pods "x" is forbidden: violates PodSecurity "restricted:latest": runAsNonRoot != true',
     "pod_security", "restricted:latest"),
    ("ReplicaSet", 'admission webhook "validate.kyverno.svc-fail" denied the request: policy require-labels failed',
     "webhook_denied", "validate.kyverno.svc-fail"),
    ("ReplicaSet", 'Internal error occurred: failed calling webhook "mutate.example.io": no route',
     "webhook_unreachable", "mutate.example.io"),
    ("ReplicaSet", 'pods "x" is forbidden: error looking up service account shop/runner: serviceaccount "runner" not found',
     "serviceaccount_missing", "runner"),
    ("Job", 'forbidden: User "system:serviceaccount:ci:deployer" cannot create resource "pods" in API group ""',
     "rbac_forbidden", "system:serviceaccount:ci:deployer"),
    ("Deployment", 'Deployment.apps "x" is invalid: spec.template.spec.containers[0].image: Required value',
     "invalid_spec", "spec.template.spec.containers[0].image"),
])
def test_admission(kind: str, msg: str, sub: str, detail: str) -> None:
    f = one(AdmissionRule(), ev(events=(e(kind, "x", "FailedCreate", msg),), available=frozenset({"events"})))
    assert f.sub_cause == sub and f.details["detail"] == detail


def test_admission_reads_replica_failure_condition_and_ignores_normal_events() -> None:
    ws = WorkloadStatus(conditions=(Condition(type="ReplicaFailure", status="True",
                                              message="pods is forbidden: exceeded quota: q1"),))
    assert one(AdmissionRule(), ev(workload=ws)).sub_cause == "quota"
    assert AdmissionRule().evaluate(ev(events=(e("ReplicaSet", "x", "SuccessfulCreate",
                                                 "exceeded quota", type_="Normal"),))) == []


# --- PRB-001 ---------------------------------------------------------------------------------

@pytest.mark.parametrize(("msg", "sub"), [
    ("Liveness probe failed: HTTP probe failed with statuscode: 404", "liveness_http_404"),
    ("Readiness probe failed: HTTP probe failed with statuscode: 503", "readiness_http_503"),
    ("Readiness probe failed: Get http://10.0.0.1:3000/: dial tcp: connect: connection refused", "readiness_connection_refused"),
    ("Liveness probe failed: Get \"http://x/\": context deadline exceeded (Client.Timeout exceeded)", "liveness_timeout"),
    ("Startup probe failed: HTTP probe failed with statuscode: 500", "startup_http_500"),
    ("Readiness probe failed: unexpected thing", "readiness_failed"),
])
def test_probe(msg: str, sub: str) -> None:
    assert one(ProbeRule(), ev(events=(e(reason="Unhealthy", msg=msg),))).sub_cause == sub


def test_probe_negative() -> None:
    assert ProbeRule().evaluate(ev(events=(e(reason="Unhealthy", msg="something else"),
                                           e(reason="Started", msg="Liveness probe failed")))) == []


# --- STO-001 / STO-002 ------------------------------------------------------------------------

@pytest.mark.parametrize(("events", "sub"), [
    ((e("PersistentVolumeClaim", "data", "ProvisioningFailed", 'storageclass.storage.k8s.io "fast" not found'),), "storageclass_missing"),
    ((e("PersistentVolumeClaim", "data", "FailedBinding", "no persistent volumes available for this claim and no storage class is set"),), "no_storage_class"),
    ((e("PersistentVolumeClaim", "data", "ProvisioningFailed", "failed to provision volume: quota"),), "provisioning_failed"),
    ((e("PersistentVolumeClaim", "data", "WaitForFirstConsumer", "waiting for first consumer to be created before binding", "Normal"),), "waiting_for_consumer"),
    ((), "pending_unexplained"),
])
def test_pending_pvc(events, sub: str) -> None:
    pvc = PvcEvidence(name="data", namespace="ns", phase="Pending")
    assert one(PendingPvcRule(), ev(pvcs=(pvc,), events=events)).sub_cause == sub


def test_bound_pvc_is_not_reported() -> None:
    assert PendingPvcRule().evaluate(ev(pvcs=(PvcEvidence(name="d", namespace="n", phase="Bound"),))) == []


@pytest.mark.parametrize(("msg", "sub"), [
    ("Multi-Attach error for volume \"pvc-1\" Volume is already exclusively attached to one node", "multi_attach"),
    ('MountVolume.SetUp failed for volume "cfg" : configmap "app-config" not found', "source_missing"),
    ('persistentvolumeclaim "data" not found', "pvc_not_found"),
    ("pod has unbound immediate PersistentVolumeClaims", "pvc_unbound"),
    ("mkdir /data: permission denied", "permission"),
    ("AttachVolume.Attach failed for volume pvc-1: rpc error", "attach_failed"),
    ("Unable to attach or mount volumes: timed out waiting for the condition", "mount_timeout"),
    ("weird mount thing", "mount_failed"),
])
def test_mount_failures(msg: str, sub: str) -> None:
    assert one(MountFailureRule(), ev(events=(e(reason="FailedMount", msg=msg),))).sub_cause == sub


# --- NET-001 / NET-002 ------------------------------------------------------------------------

def svc(selector, ready=0):
    return ServiceEvidence(name="web", namespace="ns", selector=selector, ready_endpoints=ready)


def lpod(labels, ready):
    p = pod(containers=[ctr(ready=ready)])
    return p.model_copy(update={"labels": labels})


def test_service_selector_mismatch_pods_not_ready_and_healthy() -> None:
    pods = (lpod({"app": "web"}, False),)
    mismatch = one(ServiceEndpointsRule(), ev(services=(svc({"app": "wrong"}),), pods=pods))
    assert mismatch.sub_cause == "selector_mismatch" and mismatch.confidence == "high"
    notready = one(ServiceEndpointsRule(), ev(services=(svc({"app": "web"}),), pods=pods))
    assert notready.sub_cause == "pods_not_ready" and notready.outcome_only
    assert ServiceEndpointsRule().evaluate(ev(services=(svc({"app": "web"}, ready=2),), pods=pods)) == []
    assert ServiceEndpointsRule().evaluate(ev(services=(svc({}),), pods=pods)) == []


@pytest.mark.parametrize(("msg", "sub"), [
    ("Failed to create pod sandbox: failed to assign an IP address to container", "ip_exhausted"),
    ("Failed to create pod sandbox: network plugin is not ready: cni plugin not initialized", "network_plugin"),
    ("Failed to create pod sandbox: weird", "sandbox_failure"),
])
def test_cni(msg: str, sub: str) -> None:
    assert one(CniRule(), ev(events=(e(reason="FailedCreatePodSandBox", msg=msg),))).sub_cause == sub


# --- WL-* ------------------------------------------------------------------------------------

def test_workload_outcomes_are_not_root_causes() -> None:
    ws = WorkloadStatus(conditions=(
        Condition(type="ReplicaFailure", status="True", message="forbidden password=hunter2-canary"),
        Condition(type="Progressing", status="False", reason="ProgressDeadlineExceeded")))
    rf = one(ReplicaFailureRule(), ev(workload=ws))
    assert rf.outcome_only and "hunter2" not in str(rf.details)
    assert one(ProgressDeadlineRule(), ev(workload=ws)).outcome_only
    assert ReplicaFailureRule().evaluate(ev(workload=WorkloadStatus())) == []


def test_job_failures() -> None:
    def job(reason):
        return JobEvidence(name="j", namespace="n", conditions=(
            Condition(type="Failed", status="True", reason=reason),))
    d = one(JobFailureRule(), ev(jobs=(job("DeadlineExceeded"),)))
    b = one(JobFailureRule(), ev(jobs=(job("BackoffLimitExceeded"),)))
    assert (d.sub_cause, d.outcome_only) == ("deadline_exceeded", False)
    assert (b.sub_cause, b.outcome_only) == ("backoff_limit", True)
    assert JobFailureRule().evaluate(ev(jobs=(JobEvidence(name="j", namespace="n"),))) == []


# --- APP-* (log signatures) -------------------------------------------------------------------

def logs(*lines, previous=True):
    return ev(logs=(ContainerLog(pod="p", container="web", previous=previous, lines=tuple(lines)),))


@pytest.mark.parametrize(("line", "sub", "detail"), [
    ("ModuleNotFoundError: No module named 'fastapi'", "module_not_found", "fastapi"),
    ("ImportError: cannot import name 'Foo' from 'bar'", "import_error", "Foo"),
    ("  SyntaxError: invalid syntax", "syntax_error", None),
    ("KeyError: 'DATABASE_URL'", "missing_env", "DATABASE_URL"),
    ("OSError: [Errno 98] Address already in use", "address_in_use", None),
])
def test_python_logs(line: str, sub: str, detail: str | None) -> None:
    f = one(PythonLogRule(), logs("starting", line))
    assert f.sub_cause == sub and f.details.get("detail") == detail and f.confidence != "high"
    assert f.evidence_refs == ("pod/p/container/web/previous",)


@pytest.mark.parametrize(("line", "sub"), [
    ("Error: Cannot find module 'next'", "module_not_found"),
    ("Error: listen EADDRINUSE: address already in use :::3000", "port_in_use"),
    ("FATAL ERROR: Reached heap limit - JavaScript heap out of memory", "heap_oom"),
    ("Error: listen EACCES: permission denied 0.0.0.0:80", "permission"),
])
def test_node_logs(line: str, sub: str) -> None:
    assert one(NodeLogRule(), logs(line)).sub_cause == sub


def test_network_logs_and_negatives() -> None:
    assert one(NetworkLogRule(), logs("getaddrinfo ENOTFOUND backend")).sub_cause == "dns_failure"
    assert one(NetworkLogRule(), logs("connect ECONNREFUSED 10.0.0.1:5432")).sub_cause == "connection_refused"
    for rule in (PythonLogRule(), NodeLogRule(), NetworkLogRule()):
        assert rule.evaluate(logs("all good", "listening on 3000")) == []


def test_log_rules_never_reflect_log_lines_or_attacker_names() -> None:
    f = one(PythonLogRule(), logs("ModuleNotFoundError: No module named '<script>alert(1)</script>'"))
    assert "<" not in f.summary and f.details.get("detail") is None
