"""NET-001 services without ready endpoints; NET-002 CNI / sandbox failures."""
from __future__ import annotations

from collections.abc import Iterable

from ..models import Evidence, Finding
from .table import TableRule, sub


class ServiceEndpointsRule:
    id = "NET-001"
    priority = 60
    requires = frozenset({"services", "pods"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        out: list[Finding] = []
        for svc in ev.services:
            if svc.ready_endpoints > 0 or not svc.selector:
                continue  # healthy, or selector-less (headless/external): not diagnosable here
            sel = ",".join(f"{k}={v}" for k, v in sorted(svc.selector.items()))
            matching = [p for p in ev.pods if svc.selector.items() <= p.labels.items()]
            if not matching:
                sub_cause, conf = "selector_mismatch", "high"
                text = f"Service {svc.name} selects {sel}, which matches none of the workload's pods"
                nxt = "Make the Service selector match the pod labels in the chart"
            elif not any(all(c.ready for c in p.containers if not c.is_init) and p.phase == "Running"
                         for p in matching):
                sub_cause, conf = "pods_not_ready", "high"
                text = f"Service {svc.name} has no ready endpoints because its pods are not Ready"
                nxt = "Fix why the pods are not Ready (see the other findings)"
            else:
                sub_cause, conf = "endpoints_not_published", "low"
                text = f"Service {svc.name} shows no ready endpoints although matching pods look Ready"
                nxt = "Re-check shortly; endpoint publication may lag"
            out.append(Finding(
                rule_id=self.id, sub_cause=sub_cause, confidence=conf, summary=text, next_action=nxt,
                evidence_refs=(f"service/{svc.name}",), causal_order=55, priority=self.priority,
                outcome_only=(sub_cause == "pods_not_ready"),
            ))
        return sorted(out, key=lambda f: f.evidence_refs)


class CniRule(TableRule):
    id, priority, causal_order = "NET-002", 66, 14
    requires = frozenset({"events"})
    table = (
        sub("ip_exhausted", r"failed to assign an IP address|no available IP|IPAM|ip addresses exhausted|failed to allocate",
            "high", "The cluster network ran out of pod IP addresses",
            "Free IPs, enlarge the pod CIDR/subnet, or add nodes"),
        sub("network_plugin", r"network plugin is not ready|cni plugin not initialized|NetworkPluginNotReady|failed to set up sandbox container|plugin type=",
            "medium", "The CNI network plugin failed to set up the pod network",
            "Check the CNI pods and node network configuration"),
        sub("sandbox_failure", r".", "low", "The pod sandbox could not be created",
            "Read the FailedCreatePodSandBox event for the cause"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        for e in ev.events:
            if e.object_kind == "Pod" and (
                e.reason in ("FailedCreatePodSandBox", "NetworkNotReady", "FailedCreatePodSandbox")
            ):
                yield f"event/Pod/{e.object_name}/{e.reason}", f"{e.reason}: {e.message}"
