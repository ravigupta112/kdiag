"""Minimal text renderer: answer first, details after."""
from __future__ import annotations

from .models import DiagnosisReport

_HEAD = {
    "diagnosed": "DIAGNOSED", "partial": "PARTIAL RESULT", "unknown": "CAUSE UNKNOWN",
    "no_issue_detected": "NO ISSUE DETECTED", "target_not_found": "TARGET NOT FOUND",
    "ambiguous_target": "MULTIPLE MATCHES", "cluster_unreachable": "CLUSTER UNREACHABLE",
}


def render_text(r: DiagnosisReport) -> str:
    name = f"{r.target.name} ({r.target.namespace or '?'})" if r.target else "deployment"
    out = [f"{_HEAD[r.status]}: {name}"]
    if r.status == "unknown":
        out.append("No rule matched the evidence. Nothing is being guessed.")
    if r.primary:
        p = r.primary
        out += [f"CAUSE   {p.summary}", f"        confidence: {p.confidence.upper()}  rule: {p.rule_id}",
                f"NEXT    {p.next_action}"]
    if r.candidates:
        out += ["Pick one:", *[f"  - {c}" for c in r.candidates]]
    if r.supporting:
        out.append(f"SUPPORTING ({len(r.supporting)})")
        out += [f"  - [{f.rule_id}] {f.summary}" for f in r.supporting]
    if r.partial_errors:
        out.append("NOT COLLECTED")
        out += [f"  - {e.resource}: {e.reason}" + (" (retry may help)" if e.retryable else "")
                + (" (optional read)" if e.optional else "")
                for e in r.partial_errors]
    if r.skipped_rules:
        by_kind: dict[str, list[str]] = {}
        for sk in r.skipped_rules:
            by_kind.setdefault(", ".join(sk.missing), []).append(sk.rule_id)
        out.append(f"RULES SKIPPED ({len(r.skipped_rules)}, missing evidence)")
        out += [f"  - needs {kind}: {', '.join(sorted(ids))}" for kind, ids in sorted(by_kind.items())]
    if r.notes:
        out.append("NOTES")
        out += [f"  - {n}" for n in r.notes]
    if r.rule_errors:
        out.append(f"RULE ERRORS: {', '.join(r.rule_errors)}")
    if r.truncated:
        out.append("NOTE: evidence or report was truncated to fit limits")
    return "\n".join(out)
