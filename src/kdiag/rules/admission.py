"""ADM-001: quota, LimitRange, PodSecurity, webhooks, ServiceAccount, RBAC, invalid specs."""
from __future__ import annotations

from collections.abc import Iterable

from ..models import Evidence
from .table import TableRule, sub

_N = r"([A-Za-z0-9._-]{1,253})"
_KINDS = {"ReplicaSet", "StatefulSet", "Job", "DaemonSet", "Pod", "Deployment", "CronJob"}


class AdmissionRule(TableRule):
    id, priority, causal_order = "ADM-001", 85, 12
    requires = frozenset({"events"})
    table = (
        sub("quota", r"exceeded quota", "high",
            "A ResourceQuota ({detail}) blocks creating more pods or resources",
            "Raise the quota, lower requests/limits, or free resources in the namespace",
            rf"exceeded quota: {_N}"),
        sub("limit_range",
            r"(?:minimum|maximum) (?:cpu|memory|ephemeral-storage) usage per (?:Container|Pod)|LimitRange",
            "high", "A LimitRange rejects the pod's resource settings ({detail})",
            "Adjust requests/limits to fit the namespace LimitRange",
            r"((?:minimum|maximum) (?:cpu|memory|ephemeral-storage) usage per (?:Container|Pod))"),
        sub("pod_security", r"violates PodSecurity", "high",
            "Pod Security admission rejected the pod (policy {detail})",
            "Fix the pod securityContext (runAsNonRoot, privileges, hostNetwork) or the namespace level",
            r"PodSecurity \"([a-z]+:[a-z0-9.]+)\""),
        sub("webhook_denied", r"admission webhook \"[^\"]+\" denied the request", "high",
            "Admission webhook {detail} (a policy engine such as Kyverno or Gatekeeper) denied the request",
            "Read the policy message in the event; fix the manifest or the policy",
            rf"admission webhook \"{_N}\" denied"),
        sub("webhook_unreachable", r"failed calling webhook|no endpoints available for service", "high",
            "An admission webhook ({detail}) could not be reached, so requests are rejected",
            "Check the webhook service and its pods, or its failurePolicy",
            rf"failed calling webhook \"{_N}\""),
        sub("serviceaccount_missing", r"serviceaccount \"[^\"]+\" not found", "high",
            "The ServiceAccount {detail} does not exist, so pods cannot be created",
            "Create the ServiceAccount or fix serviceAccountName in the chart",
            rf"serviceaccount \"{_N}\" not found"),
        sub("rbac_forbidden", r"forbidden: User \"[^\"]+\" cannot", "high",
            "The identity {detail} lacks permission for an API call",
            "Grant the needed role or fix the ServiceAccount used by the deployment",
            r"User \"([A-Za-z0-9._:@/-]{1,253})\" cannot"),
        sub("invalid_spec", r"Invalid value|is invalid|Required value", "medium",
            "The API server rejected the spec at {detail}",
            "Fix the manifest field named in the event",
            r"(spec\.[A-Za-z0-9_.\[\]-]{1,200})"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        for e in ev.events:
            if e.type == "Warning" and e.object_kind in _KINDS:
                yield f"event/{e.object_kind}/{e.object_name}/{e.reason}", e.message
        if ev.workload:
            for c in ev.workload.conditions:
                if c.type == "ReplicaFailure" and c.status == "True" and c.message:
                    yield "workload/ReplicaFailure", c.message
