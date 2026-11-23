"""Metrics hooks. Metric names and labels never contain evidence content, only enums and rule ids."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Protocol


class Metrics(Protocol):
    def inc(self, name: str, value: float = 1, **labels: str) -> None: ...

    def observe(self, name: str, value: float, **labels: str) -> None: ...


# Every metric kdiag emits. A test fails if code, alerts or docs reference a name not listed here.
METRIC_NAMES: tuple[str, ...] = (
    "kdiag_diagnosis_total", "kdiag_diagnosis_duration_seconds", "kdiag_unknown_cause_total",
    "kdiag_truncated_total", "kdiag_masking_events_total", "kdiag_report_bytes",
    "kdiag_partial_reads_total", "kdiag_timeouts_total", "kdiag_rule_exceptions_total",
    "kdiag_rule_matches_total", "kdiag_k8s_api_calls_total", "kdiag_k8s_api_errors_total",
    "kdiag_http_requests_total", "kdiag_rate_limited_total", "kdiag_backpressure_total",
    "kdiag_cache_total", "kdiag_snapshot_total", "kdiag_snapshot_bytes",
    "kdiag_persistence_errors_total", "kdiag_snapshot_unreadable_total",
    "kdiag_retention_deleted_total", "kdiag_prompt_exports_total", "kdiag_kubeconfig_rejected_total",
)


class AuditSink(Protocol):
    """Records who read what. Fields must be identifiers (resource, namespace), never content."""

    def record(self, event: str, **fields: str) -> None: ...


class NullAudit:
    def record(self, event: str, **fields: str) -> None:
        return None


class NullMetrics:
    def inc(self, name: str, value: float = 1, **labels: str) -> None:
        return None

    def observe(self, name: str, value: float, **labels: str) -> None:
        return None


class InMemoryMetrics:
    """For tests and local debugging."""

    def __init__(self) -> None:
        self.counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self.observations: dict[str, list[float]] = defaultdict(list)

    def inc(self, name: str, value: float = 1, **labels: str) -> None:
        self.counters[(name, tuple(sorted(labels.items())))] += value

    def observe(self, name: str, value: float, **labels: str) -> None:
        self.observations[name].append(value)

    def count(self, name: str, **labels: str) -> float:
        """Sum of counters with this name whose labels include the given ones."""
        want = set(labels.items())
        return sum(v for (n, lab), v in self.counters.items() if n == name and want <= set(lab))


class PrometheusMetrics:
    """Optional: requires `prometheus-client`. Instruments are created lazily per metric name."""

    def __init__(self, registry: Any = None, prefix: str = "") -> None:
        import prometheus_client as prom

        self._prom = prom
        self._registry = registry
        self._prefix = prefix
        self._counters: dict[str, Any] = {}
        self._hists: dict[str, Any] = {}
        self._labelnames: dict[str, tuple[str, ...]] = {}

    def _get(self, store: dict[str, Any], kind: str, name: str, labels: dict[str, str]) -> Any:
        names = tuple(sorted(labels))
        full = self._prefix + name
        if full not in store:
            cls = self._prom.Counter if kind == "counter" else self._prom.Histogram
            kwargs: dict[str, Any] = {"registry": self._registry} if self._registry is not None else {}
            store[full] = cls(full, full, names, **kwargs)
            self._labelnames[full] = names
        if self._labelnames[full] != names:
            raise ValueError(f"inconsistent labels for {full}")
        return store[full]

    def inc(self, name: str, value: float = 1, **labels: str) -> None:
        c = self._get(self._counters, "counter", name, labels)
        (c.labels(**labels) if labels else c).inc(value)

    def observe(self, name: str, value: float, **labels: str) -> None:
        h = self._get(self._hists, "hist", name, labels)
        (h.labels(**labels) if labels else h).observe(value)


NULL_METRICS = NullMetrics()
NULL_AUDIT = NullAudit()
