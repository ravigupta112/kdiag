"""IMG-001: image pull failures, with sub-cause classification."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Confidence, Evidence, Finding

_WAITING = {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ImageInspectError",
            "ErrImageNeverPull"}

# (sub_cause, regex) - first match wins; ambiguous registry replies come first.
_SUB: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("auth_or_not_found", re.compile(r"(?i)pull access denied|repository does not exist or may require")),
    ("auth", re.compile(r"(?i)\b(?:401|403)\b|unauthorized|authentication required|access denied|denied: ")),
    ("not_found", re.compile(r"(?i)manifest unknown|not found|\b404\b|name unknown|does not exist")),
    ("tls", re.compile(r"(?i)x509:|certificate (?:signed by unknown authority|has expired|is valid for)")),
    ("network", re.compile(r"(?i)tls handshake timeout|no such host|i/o timeout|connection refused|timeout")),
)
_BY_REASON: dict[str, tuple[str, Confidence]] = {
    "InvalidImageName": ("invalid_name", "high"),
    "ErrImageNeverPull": ("never_pull", "high"),
    "ImageInspectError": ("inspect_error", "medium"),
}
_CONF: dict[str, Confidence] = {
    "auth": "high", "not_found": "high", "auth_or_not_found": "medium", "network": "medium",
    "tls": "high",
}
_SUMMARY = {
    "not_found": "Image {image} was not found in the registry",
    "auth": "The registry rejected the credentials used to pull {image}",
    "auth_or_not_found": "Pulling {image} was denied: either it does not exist or credentials are missing",
    "network": "The node could not reach the registry to pull {image}",
    "tls": "The node does not trust the registry's TLS certificate for {image}",
    "invalid_name": "The image name {image} is invalid",
    "never_pull": "Image {image} is not on the node and imagePullPolicy is Never",
    "inspect_error": "The image {image} exists but could not be inspected",
    "generic": "Pulling image {image} failed for a reason the message does not classify",
}
_NEXT = {
    "not_found": "Check that the tag exists in the registry and that image.repository/tag in the chart values are correct",
    "auth": "Check the imagePullSecret referenced by the pod and its registry credentials",
    "auth_or_not_found": "Check the repository name and tag, then the imagePullSecret",
    "network": "Check registry DNS/TLS reachability from the node; retry if it looks transient",
    "tls": "Check the registry certificate, its CA trust on the nodes, and certificate expiry",
    "invalid_name": "Fix the image reference (lowercase repository, valid tag)",
    "never_pull": "Pre-load the image on the node or change imagePullPolicy",
    "inspect_error": "Check the container runtime on the node and the image manifest",
    "generic": "Read the pod's Failed events for the full pull error",
}
# Reflected into summaries, so restrict to legal image-reference characters (no markup, no spaces).
_IMAGE = re.compile(r'image "([A-Za-z0-9._:/@+-]{1,300})"')


@dataclass
class _Group:
    confidence: Confidence
    refs: list[str] = field(default_factory=list)
    image: str | None = None


def _classify(reason: str, text: str) -> tuple[str, Confidence]:
    if reason in _BY_REASON:
        return _BY_REASON[reason]
    for sub, rx in _SUB:
        if rx.search(text):
            return sub, _CONF[sub]
    return "generic", "low"


class ImageRule:
    id = "IMG-001"
    priority = 70
    requires = frozenset({"pods"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        groups: dict[str, _Group] = {}
        for pod in ev.pods:
            pod_msgs = [
                e.message for e in ev.events
                if e.object_kind == "Pod" and e.object_name == pod.name
                and e.reason in {"Failed", "BackOff"} and "image" in e.message.lower()
            ]
            for c in pod.containers:
                if c.waiting_reason not in _WAITING:
                    continue
                text = " ".join([c.waiting_message or "", *pod_msgs])
                sub, conf = _classify(c.waiting_reason or "", text)
                g = groups.setdefault(sub, _Group(confidence=conf))
                g.refs.append(f"pod/{pod.name}/container/{c.name}")
                if g.image is None and (m := _IMAGE.search(text)):
                    g.image = m.group(1)
        out: list[Finding] = []
        for sub in sorted(groups):
            g = groups[sub]
            image = g.image or "unknown"
            out.append(Finding(
                rule_id=self.id, sub_cause=sub, confidence=g.confidence,
                summary=_SUMMARY[sub].format(image=image), next_action=_NEXT[sub],
                evidence_refs=tuple(sorted(g.refs)), causal_order=20, priority=self.priority,
                details={"image": image},
            ))
        return out
