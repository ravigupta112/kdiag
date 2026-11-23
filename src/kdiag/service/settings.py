from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..models import Limits


def _bool(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class ServiceSettings:
    """Server-side configuration. Nothing here is accepted from request data."""

    enabled: bool = True  # feature flag: when off, every route answers 404 "disabled"
    shadow_mode: bool = False  # run diagnoses and record metrics, but return 202 with no report
    allow_kubeconfig_upload: bool = False  # off by default; needs security approval
    kubeconfig_allowed_hosts: tuple[str, ...] = ()
    kubeconfig_allow_private: bool = False
    limits: Limits = field(default_factory=Limits)
    cache_ttl_s: float = 30.0
    cache_max_entries: int = 256
    cache_max_bytes: int = 16_000_000
    max_concurrent: int = 8  # simultaneous diagnoses; beyond this requests queue briefly, then 503
    queue_wait_s: float = 2.0
    rate_per_s: float = 5.0  # per principal
    rate_burst: int = 10
    max_body_bytes: int = 2_000_000
    export_max_chars: int = 8000

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServiceSettings:
        e = os.environ if env is None else env
        d = cls()
        return cls(
            enabled=_bool(e.get("KDIAG_ENABLED"), d.enabled),
            shadow_mode=_bool(e.get("KDIAG_SHADOW_MODE"), d.shadow_mode),
            allow_kubeconfig_upload=_bool(e.get("KDIAG_ALLOW_KUBECONFIG_UPLOAD"), d.allow_kubeconfig_upload),
            kubeconfig_allowed_hosts=tuple(h.strip() for h in e.get("KDIAG_KUBECONFIG_ALLOWED_HOSTS", "").split(",") if h.strip()),
            kubeconfig_allow_private=_bool(e.get("KDIAG_KUBECONFIG_ALLOW_PRIVATE"), d.kubeconfig_allow_private),
            limits=Limits(
                max_pods=int(e.get("KDIAG_MAX_PODS", d.limits.max_pods)),
                max_events=int(e.get("KDIAG_MAX_EVENTS", d.limits.max_events)),
                request_timeout_s=float(e.get("KDIAG_REQUEST_TIMEOUT_S", d.limits.request_timeout_s)),
                overall_timeout_s=float(e.get("KDIAG_OVERALL_TIMEOUT_S", d.limits.overall_timeout_s)),
            ),
            cache_ttl_s=float(e.get("KDIAG_CACHE_TTL_S", d.cache_ttl_s)),
            cache_max_entries=int(e.get("KDIAG_CACHE_MAX_ENTRIES", d.cache_max_entries)),
            max_concurrent=int(e.get("KDIAG_MAX_CONCURRENT", d.max_concurrent)),
            queue_wait_s=float(e.get("KDIAG_QUEUE_WAIT_S", d.queue_wait_s)),
            rate_per_s=float(e.get("KDIAG_RATE_PER_S", d.rate_per_s)),
            rate_burst=int(e.get("KDIAG_RATE_BURST", d.rate_burst)),
        )
