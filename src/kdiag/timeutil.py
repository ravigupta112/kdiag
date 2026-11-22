from __future__ import annotations

from datetime import UTC, datetime


def to_utc(ts: datetime | None) -> datetime | None:
    """Naive timestamps are treated as UTC; aware ones are converted."""
    if ts is None:
        return None
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)
