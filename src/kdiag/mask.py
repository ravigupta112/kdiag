"""Secret masking. Fails closed: if masking raises, the value is dropped."""
from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
     "[REDACTED:private-key]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED:jwt]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}"
                r"|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"), "[REDACTED:token]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(
        r"""(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key"""
        r"""|private[_-]?key|credential)[A-Za-z0-9_.-]*)\s*([=:])\s*("[^"]*"|'[^']*'|[^\s,;&]+)"""),
     r"\1\2[REDACTED]"),
    # long base64/hex blobs; image digests (sha256:...) are intentionally left readable
    (re.compile(r"(?<!sha256:)\b[A-Za-z0-9+/]{40,}={0,2}"), "[REDACTED:blob]"),
)

MASK_ERROR = "[REDACTED:mask-error]"
DEFAULT_MAX_LEN = 2000


def mask_text(value: str | None, max_len: int = DEFAULT_MAX_LEN) -> str | None:
    if value is None:
        return None
    try:
        out = value[:max_len]
        for pattern, repl in _PATTERNS:
            out = pattern.sub(repl, out)
        return out
    except Exception:  # noqa: BLE001 - fail closed on any masking failure
        return MASK_ERROR
