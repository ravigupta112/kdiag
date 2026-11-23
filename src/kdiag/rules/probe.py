"""PRB-001: liveness, readiness and startup probe failures, with the failure mode."""
from __future__ import annotations

import re

from ..models import Evidence, Finding

_TYPE = re.compile(r"(Liveness|Readiness|Startup) probe (?:failed|errored)", re.IGNORECASE)
_HTTP = re.compile(r"statuscode: (\d{3})", re.IGNORECASE)
_CAUSES = (
    ("connection_refused", re.compile(r"connection refused", re.IGNORECASE),
     "the app is not listening on the probe port",
     "Check the probe port and how long the app needs to start (initialDelaySeconds/startupProbe)"),
    ("timeout", re.compile(r"timeout|deadline exceeded|Client\.Timeout", re.IGNORECASE),
     "the probe times out",
     "Raise timeoutSeconds/initialDelaySeconds or investigate slow responses"),
    ("exec_failed", re.compile(r"exec|command", re.IGNORECASE),
     "the probe command fails",
     "Run the probe command inside the container and check its exit code"),
)
_ORDER = {"startup": 33, "liveness": 35, "readiness": 38}


class ProbeRule:
    id = "PRB-001"
    priority = 55
    requires = frozenset({"events"})

    def evaluate(self, ev: Evidence) -> list[Finding]:
        groups: dict[tuple[str, str], tuple[str, str, set[str]]] = {}
        for e in ev.events:
            if e.object_kind != "Pod" or e.reason != "Unhealthy":
                continue
            t = _TYPE.search(e.message)
            if not t:
                continue
            ptype = t.group(1).lower()
            if (h := _HTTP.search(e.message)):
                code = h.group(1)
                cause = f"http_{code}"
                desc = f"the endpoint returns HTTP {code}"
                nxt = ("Check that the probe path and port exist in the app" if code == "404"
                       else "The app answers the probe with an error; check its logs and dependencies"
                       if code.startswith("5") else "Check the probe path, port and expected status")
            else:
                cause, desc, nxt = "failed", "the probe fails for an unclassified reason", \
                    "Read the probe failure event for details"
                for name, rx, d, n in _CAUSES:
                    if rx.search(e.message):
                        cause, desc, nxt = name, d, n
                        break
            key = (ptype, cause)
            groups.setdefault(key, (desc, nxt, set()))[2].add(f"pod/{e.object_name}")
        out: list[Finding] = []
        for (ptype, cause), (desc, nxt, refs) in sorted(groups.items()):
            out.append(Finding(
                rule_id=self.id, sub_cause=f"{ptype}_{cause}", confidence="high",
                summary=f"{ptype.capitalize()} probe is failing: {desc}", next_action=nxt,
                evidence_refs=tuple(sorted(refs)), causal_order=_ORDER[ptype], priority=self.priority,
            ))
        return out
