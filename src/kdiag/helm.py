"""Helm / deployment-log parser. Table driven, linear-time regexes, unknown by default."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Confidence, Finding

MAX_CHARS = 200_000  # keep the tail: errors are at the end of CI logs

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")
_CI_TS = re.compile(r"^\s*\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+", re.MULTILINE)
_WS = re.compile(r"[ \t]+")


@dataclass(frozen=True)
class _Pattern:
    id: str
    sub: str
    regex: re.Pattern[str]
    confidence: Confidence
    definitive: bool
    summary: str
    next_action: str


def _p(id_: str, sub: str, rx: str, conf: Confidence, definitive: bool, summary: str, nxt: str) -> _Pattern:
    return _Pattern(id_, sub, re.compile(rx, re.IGNORECASE), conf, definitive, summary, nxt)


# Order matters: most specific first.
PATTERNS: tuple[_Pattern, ...] = (
    _p("HLM-003", "release_locked",
       r"another operation \((?:install|upgrade|rollback)[^)\n]{0,40}\) is in progress"
       r"|release [^\n]{0,80}status: pending-(?:install|upgrade|rollback)",
       "high", True, "Another Helm operation holds the release lock",
       "Wait for the other operation, or inspect the release for a stuck pending-* state"),
    _p("HLM-006", "ownership_conflict",
       r"exists and cannot be imported into the current release"
       r"|rendered manifests contain a resource that already exists",
       "high", True, "A rendered resource already exists outside this Helm release",
       "Remove or adopt the existing resource, or choose a different name"),
    _p("HLM-005", "name_in_use", r"cannot re-use a name that is still in use",
       "high", True, "A Helm release with this name already exists",
       "Use `upgrade` for the existing release or pick another release name"),
    _p("HLM-002", "release_not_found",
       r"release: not found|has no deployed releases",
       "high", True, "Helm could not find the release",
       "Check the release name and namespace"),
    _p("HLM-004", "yaml_error",
       r"^\s*Error:[^\n]{0,300}?(?:mapping values are not allowed|did not find expected key"
       r"|could not find expected|yaml: line \d+)",
       "high", True, "Chart or values YAML is malformed",
       "Fix the YAML syntax at the line reported in the Helm output"),
    _p("HLM-004", "template_error",
       r"^\s*Error:[^\n]{0,300}?(?:parse error|error calling \w+|failed to render"
       r"|template: [^\n]{0,200}executing)|parse error at \(",
       "high", True, "Helm could not render the chart templates",
       "Check template syntax and that values match the types the chart expects"),
    _p("HLM-010", "manifest_rejected",
       r"^\s*Error:[^\n]{0,300}?(?:is invalid|Invalid value|Required value|failed to create resource)",
       "high", True, "The Kubernetes API rejected a rendered manifest",
       "Read the field path in the error and fix the chart values or templates"),
    _p("HLM-011", "unknown_kind",
       r"no matches for kind|resource mapping not found|unable to recognize|server doesn't have a resource type",
       "high", True, "A rendered resource uses a kind or apiVersion the cluster does not know",
       "Install the missing CRD or fix apiVersion/kind in the chart"),
    _p("HLM-012", "chart_not_found",
       r"^\s*Error:[^\n]{0,200}?(?:chart [^\n]{0,100}not found|failed to download|path \"[^\"]+\" not found)",
       "high", True, "Helm could not find or download the chart",
       "Check the chart name, version, repository and path"),
    _p("HLM-014", "namespace_not_found",
       r"namespace \"[^\"]+\" (?:does not exist|not found)|namespaces \"[^\"]+\" not found",
       "high", True, "The target namespace does not exist",
       "Create the namespace or enable create-namespace"),
    _p("HLM-007", "namespace_terminating",
       r"because it is being terminated|namespace \"?[a-z0-9-]+\"? is (?:being )?terminating",
       "high", True, "The target namespace is terminating",
       "Wait for the namespace deletion to finish, or use another namespace"),
    _p("HLM-001", "wait_timeout", r"timed out waiting for the condition",
       "medium", False, "Helm gave up waiting for resources to become ready (an outcome, not a cause)",
       "Look at the cluster findings to see which resource never became ready"),
    _p("HLM-009", "deadline_exceeded", r"context deadline exceeded",
       "low", False, "A Helm or API call hit its deadline (wait timeout or API server slowness)",
       "Check API server reachability and rerun; compare with cluster findings"),
)

# A success line after an error means that error was a retried/recovered step, not the failure.
_SUCCESS = re.compile(r"has been (?:upgraded|installed)\b|STATUS: deployed", re.IGNORECASE)

_RESOURCE = re.compile(
    r"\b(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|Service|PersistentVolumeClaim"
    r"|ConfigMap|Ingress)/([a-z0-9][a-z0-9.-]{0,251})")
_NAMESPACE = re.compile(r"in namespace \"([a-z0-9-]{1,63})\"|(?:--namespace|-n)[= ]([a-z0-9-]{1,63})")


@dataclass(frozen=True)
class ParseResult:
    kind: str  # pattern id, or "unknown"
    sub_cause: str = "unknown"
    confidence: Confidence = "low"
    definitive: bool = False
    summary: str = ""
    next_action: str = ""
    extracted: dict[str, tuple[str, ...]] = field(default_factory=dict)
    all_matches: tuple[str, ...] = ()
    resolved: tuple[str, ...] = ()  # matches ignored because a success line followed them
    truncated: bool = False


def clean(text: str) -> tuple[str, bool]:
    truncated = len(text) > MAX_CHARS
    text = text[-MAX_CHARS:] if truncated else text
    text = _ANSI.sub("", text).replace("\r", "")
    text = _CI_TS.sub("", text)
    return _WS.sub(" ", text), truncated


def parse_helm(text: str | None) -> ParseResult:
    if not text or not text.strip():
        return ParseResult(kind="unknown")
    cleaned, truncated = clean(text)
    last_ok = max((m.end() for m in _SUCCESS.finditer(cleaned)), default=-1)
    hits: list[tuple[_Pattern, int]] = []
    resolved: list[str] = []
    for pat in PATTERNS:
        last = None
        for last in pat.regex.finditer(cleaned):
            pass
        if last is None:
            continue
        if last.start() < last_ok:
            resolved.append(f"{pat.id}:{pat.sub}")
        else:
            hits.append((pat, last.start()))
    extracted: dict[str, tuple[str, ...]] = {}
    resources = sorted({f"{k}/{n}" for k, n in _RESOURCE.findall(cleaned)})[:20]
    if resources:
        extracted["resources"] = tuple(resources)
    ns = sorted({a or b for a, b in _NAMESPACE.findall(cleaned)})[:5]
    if ns:
        extracted["namespaces"] = tuple(ns)
    if not hits:
        return ParseResult(kind="unknown", extracted=extracted, resolved=tuple(resolved),
                           truncated=truncated)
    # definitive first; among equals the most recent occurrence wins
    hits.sort(key=lambda h: (not h[0].definitive, -h[1]))
    top = hits[0][0]
    return ParseResult(
        kind=top.id, sub_cause=top.sub, confidence=top.confidence, definitive=top.definitive,
        summary=top.summary, next_action=top.next_action, extracted=extracted,
        all_matches=tuple(f"{h[0].id}:{h[0].sub}" for h in hits), resolved=tuple(resolved),
        truncated=truncated,
    )


def helm_finding(result: ParseResult) -> Finding | None:
    if result.kind == "unknown":
        return None
    details = {k: ", ".join(v) for k, v in result.extracted.items()}
    return Finding(
        rule_id=result.kind, sub_cause=result.sub_cause, confidence=result.confidence,
        summary=result.summary, next_action=result.next_action,
        evidence_refs=("helm_output",), definitive=result.definitive,
        outcome_only=not result.definitive, causal_order=0 if result.definitive else 100,
        priority=100 if result.definitive else 10, details=details,
    )
