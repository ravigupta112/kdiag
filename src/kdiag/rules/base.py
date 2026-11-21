from __future__ import annotations

from typing import Protocol

from ..models import Evidence, Finding


class Rule(Protocol):
    id: str
    priority: int
    requires: frozenset[str]

    def evaluate(self, ev: Evidence) -> list[Finding]: ...


class Registry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"duplicate rule id: {rule.id}")
        self._rules[rule.id] = rule

    def all(self) -> list[Rule]:
        return [self._rules[k] for k in sorted(self._rules)]
