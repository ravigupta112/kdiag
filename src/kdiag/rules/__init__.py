from __future__ import annotations

from .base import Registry, Rule
from .crashloop import CrashLoopRule
from .image import ImageRule
from .oom import OOMKilledRule
from .sched import UnschedulableRule


def default_registry() -> Registry:
    reg = Registry()
    for rule in (ImageRule(), OOMKilledRule(), CrashLoopRule(), UnschedulableRule()):
        reg.register(rule)
    return reg


__all__ = ["Registry", "Rule", "default_registry"]
