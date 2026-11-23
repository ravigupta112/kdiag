"""CFG-001 missing config references; POD-002 container start failures."""
from __future__ import annotations

from collections.abc import Iterable

from ..models import Evidence
from .table import TableRule, pod_events, sub

_N = r"([A-Za-z0-9._-]{1,253})"


class MissingConfigRule(TableRule):
    id, priority, causal_order = "CFG-001", 70, 25
    table = (
        sub("secret_not_found", r"secret \"[^\"]+\" not found", "high",
            "The pod references Secret {detail}, which does not exist in the namespace",
            "Create the Secret or fix the reference in the chart (kdiag never reads Secret contents)",
            rf"secret \"{_N}\" not found"),
        sub("configmap_not_found", r"configmap \"[^\"]+\" not found", "high",
            "The pod references ConfigMap {detail}, which does not exist in the namespace",
            "Create the ConfigMap or fix the reference in the chart",
            rf"configmap \"{_N}\" not found"),
        sub("key_missing", r"couldn't find key", "high",
            "A referenced Secret or ConfigMap exists but lacks the key {detail}",
            "Add the key to the Secret/ConfigMap or fix the key name in the chart",
            r"couldn't find key ([A-Za-z0-9._-]{1,253}) in (?:Secret|ConfigMap)"),
        sub("config_error", r".", "medium",
            "The container cannot be created because of a configuration error",
            "Read the pod's events for the exact message"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        for p in ev.pods:
            for c in p.containers:
                if c.waiting_reason == "CreateContainerConfigError":
                    yield f"pod/{p.name}/container/{c.name}", c.waiting_message or "config error"
        for ref, text in pod_events(ev, {"Pod"}, {"Failed"}):
            if "not found" in text or "couldn't find key" in text:  # skip unrelated Failed events
                yield ref, text


class ContainerStartRule(TableRule):
    id, priority, causal_order = "POD-002", 65, 28
    table = (
        sub("exec_format", r"exec format error", "high",
            "The image was built for a different CPU architecture than the node",
            "Rebuild the image for the node architecture (for example linux/amd64 vs arm64)"),
        sub("exec_not_found", r"executable file not found|exec: \"[^\"]+\": (?:executable file )?not found",
            "high", "The container command or entrypoint does not exist in the image",
            "Check command/args in the chart and the image's ENTRYPOINT"),
        sub("no_such_file", r"no such file or directory", "medium",
            "The container failed to start: a required file or directory is missing",
            "Check the entrypoint path and volume mount paths"),
        sub("permission_denied", r"permission denied", "medium",
            "The container failed to start with a permission error",
            "Check file permissions, runAsUser/fsGroup and the image's user"),
        sub("runtime_error", r".", "low",
            "The container runtime failed to create or start the container",
            "Read the container status message for the runtime error"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        for p in ev.pods:
            for c in p.containers:
                ref = f"pod/{p.name}/container/{c.name}"
                if c.waiting_reason in ("CreateContainerError", "RunContainerError"):
                    yield ref, c.waiting_message or "runtime error"
                if c.terminated_reason == "StartError":
                    yield ref, c.terminated_message or "start error"
                if c.last_terminated_reason == "StartError":
                    yield ref, c.last_terminated_message or "start error"
