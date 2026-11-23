"""Secret masking. Fails closed: if masking raises, the value is dropped.

Order matters: mask first, truncate last. Truncating first can cut a secret in half so that
neither half matches a pattern. Input is pre-cut to 2x the output limit to bound work.
All quantifiers are bounded so cost stays linear in input size.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_KEYS = (r"password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
         r"|credential|cookie|authorization")

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)"),
     "[REDACTED:private-key]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED:jwt]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}"
                r"|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"), "[REDACTED:token]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(://)[^/\s:@]{1,200}:[^/\s@]{1,200}@"), r"\1[REDACTED]@"),
    (re.compile(
        r"(?i)\b([A-Za-z0-9_.-]{0,64}?(?:" + _KEYS + r")[A-Za-z0-9_.-]{0,64})\s{0,3}([=:])\s{0,3}"
        r"""("[^"]{0,500}"|'[^']{0,500}'|[^\s,;&]{1,500})"""),
     r"\1\2[REDACTED]"),
    # long base64/hex blobs; image digests (sha256:...) are intentionally left readable
    (re.compile(r"(?<!sha256:)\b[A-Za-z0-9+/]{40,}={0,2}"), "[REDACTED:blob]"),
)

MASK_ERROR = "[REDACTED:mask-error]"
_COUNTER: ContextVar[list[int] | None] = ContextVar("kdiag.mask_counter", default=None)


@contextmanager
def track_masking() -> Iterator[list[int]]:
    """Counts how many strings had something redacted inside the block (for metrics)."""
    box = [0]
    token = _COUNTER.set(box)
    try:
        yield box
    finally:
        _COUNTER.reset(token)


def _bump() -> None:
    box = _COUNTER.get()
    if box is not None:
        box[0] += 1

DEFAULT_MAX_LEN = 2000


def mask_text(value: str | None, max_len: int = DEFAULT_MAX_LEN) -> str | None:
    if value is None:
        return None
    try:
        out = value[: max_len * 2]
        before = out
        for pattern, repl in _PATTERNS:
            out = pattern.sub(repl, out)
        if out != before:
            _bump()
        return out[:max_len]
    except Exception:  # noqa: BLE001 - fail closed on any masking failure
        _bump()
        return MASK_ERROR


def contains_secret(text: str) -> bool:
    """Detection only: True if text still looks sensitive. Already-redacted values do not count."""
    try:
        for pattern, _ in _PATTERNS:
            for m in pattern.finditer(text):
                if "[REDACTED" not in m.group(0):
                    return True
        return False
    except Exception:  # noqa: BLE001 - when in doubt, treat as sensitive
        return True
