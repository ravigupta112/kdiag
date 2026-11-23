"""Table-driven rule base: classifiers live in data, so adding a sub-cause is one table row.

Detail captures are reflected into summaries, so every `detail` regex must capture only a
restricted character class (names, paths). Free text is never reflected.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..models import Confidence, Evidence, Finding


@dataclass(frozen=True)
class Sub:
    name: str
    rx: re.Pattern[str]
    confidence: Confidence
    summary: str  # may contain {detail}
    next_action: str
    detail: re.Pattern[str] | None = None  # group 1 is the safe detail
    outcome_only: bool = False


def sub(name: str, rx: str, conf: Confidence, summary: str, nxt: str,
        detail: str | None = None, outcome_only: bool = False) -> Sub:
    return Sub(name, re.compile(rx, re.IGNORECASE), conf, summary, nxt,
               re.compile(detail, re.IGNORECASE) if detail else None, outcome_only)


@dataclass
class _Group:
    sub: Sub
    refs: set[str] = field(default_factory=set)
    detail: str | None = None


class TableRule:
    id = ""
    priority = 50
    causal_order = 50
    requires: frozenset[str] = frozenset({"pods"})
    table: tuple[Sub, ...] = ()

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:  # (evidence ref, text)
        raise NotImplementedError

    def evaluate(self, ev: Evidence) -> list[Finding]:
        groups: dict[str, _Group] = {}
        for ref, text in self.texts(ev):
            for s in self.table:
                if not s.rx.search(text):
                    continue
                g = groups.setdefault(s.name, _Group(s))
                g.refs.add(ref)
                if g.detail is None and s.detail and (m := s.detail.search(text)):
                    g.detail = m.group(1)
                break
        out: list[Finding] = []
        for name in sorted(groups):
            g = groups[name]
            detail = g.detail or "unknown"
            out.append(Finding(
                rule_id=self.id, sub_cause=name, confidence=g.sub.confidence,
                summary=g.sub.summary.format(detail=detail), next_action=g.sub.next_action,
                evidence_refs=tuple(sorted(g.refs)), causal_order=self.causal_order,
                priority=self.priority, outcome_only=g.sub.outcome_only,
                details={"detail": detail} if g.detail else {},
            ))
        return out


def pod_events(ev: Evidence, kinds: set[str], reasons: set[str] | None = None) -> Iterable[tuple[str, str]]:
    for e in ev.events:
        if e.object_kind in kinds and (reasons is None or e.reason in reasons):
            yield f"event/{e.object_kind}/{e.object_name}/{e.reason}", f"{e.reason}: {e.message}"
