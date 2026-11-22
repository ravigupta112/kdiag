"""Typed contracts. Frozen, extra-forbidden, versioned.

Deliberately absent: Secret values, env values, tokens, kubeconfigs. Pod env is
never modelled; a test asserts no field name hints at credential content.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

SCHEMA_VERSION = 1

Confidence = Literal["high", "medium", "low"]
Status = Literal[
    "diagnosed",
    "unknown",
    "partial",
    "no_issue_detected",
    "target_not_found",
    "ambiguous_target",
    "cluster_unreachable",
]
Mode = Literal["evidence", "cluster", "hybrid"]
ReadFailure = Literal["forbidden", "not_found", "timeout", "rate_limited", "unreachable", "error"]
WorkloadKind = Literal["Deployment", "StatefulSet", "Job", "CronJob"]


Name = Annotated[str, StringConstraints(max_length=253)]
# Kubernetes DNS-1123 forms. Strict so names can never smuggle selector/URL syntax into API calls.
DnsSubdomain = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")]
DnsLabel = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")]


class _M(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Target(_M):
    kind: WorkloadKind = "Deployment"
    name: DnsSubdomain
    namespace: DnsLabel | None = None


class WorkloadRef(_M):
    kind: WorkloadKind
    name: str
    namespace: str


class Condition(_M):
    type: Name
    status: Name
    reason: Name | None = None
    message: str | None = Field(default=None, max_length=20_000)


class ContainerEvidence(_M):
    name: Name
    is_init: bool = False
    ready: bool = False
    restart_count: int = 0
    waiting_reason: Name | None = None
    waiting_message: str | None = Field(default=None, max_length=20_000)
    terminated_reason: Name | None = None
    terminated_exit_code: int | None = None
    last_terminated_reason: Name | None = None
    last_exit_code: int | None = None
    memory_limit: Name | None = None


class PodEvidence(_M):
    name: Name
    namespace: Name
    phase: Name = "Unknown"
    node_name: Name | None = None
    conditions: tuple[Condition, ...] = Field(default=(), max_length=50)
    containers: tuple[ContainerEvidence, ...] = Field(default=(), max_length=50)


class WorkloadStatus(_M):
    """Rollout state of a Deployment/StatefulSet. Needed before anything can be called healthy."""

    generation: int = 0
    observed_generation: int = 0
    replicas: int = 0
    updated_replicas: int = 0
    ready_replicas: int = 0
    available_replicas: int = 0
    conditions: tuple[Condition, ...] = Field(default=(), max_length=50)


class EventEvidence(_M):
    object_kind: Name
    object_name: Name
    type: Name = "Normal"
    reason: Name = ""
    message: str = Field(default="", max_length=20_000)
    timestamp: datetime | None = None
    count: int = 1
    time_unknown: bool = False


class PartialReadError(_M):
    resource: Name
    reason: ReadFailure
    retryable: bool = False
    detail: str | None = None


class Limits(_M):
    """Hard bounds. The hosting service must set these from server config, never from a request:
    every field also has a ceiling here so a hostile caller cannot ask for unbounded work."""

    max_pods: int = Field(default=50, ge=1, le=200)  # pods analysed
    max_events: int = Field(default=500, ge=1, le=2000)  # events analysed
    # ceiling on what a source may return; selection (failing pods first) happens after
    max_pods_fetched: int = Field(default=500, ge=1, le=2000)
    max_events_fetched: int = Field(default=2000, ge=1, le=10_000)
    concurrency: int = Field(default=8, ge=1, le=32)
    request_timeout_s: float = Field(default=5.0, gt=0, le=60)
    overall_timeout_s: float = Field(default=30.0, gt=0, le=300)
    max_report_bytes: int = Field(default=262_144, ge=1024, le=2_000_000)

    @model_validator(mode="after")
    def _fetch_covers_analysis(self) -> Limits:
        if self.max_pods_fetched < self.max_pods or self.max_events_fetched < self.max_events:
            raise ValueError("fetch ceilings must be >= analysed limits")
        return self


class DiagnosisInput(_M):
    mode: Mode
    cluster_id: Name | None = None
    target: Target | None = None
    namespace: DnsLabel | None = None
    release: DnsSubdomain | None = None
    pods: tuple[PodEvidence, ...] = Field(default=(), max_length=500)
    events: tuple[EventEvidence, ...] = Field(default=(), max_length=5000)
    workload_status: WorkloadStatus | None = None
    helm_output: str | None = Field(default=None, max_length=1_000_000)
    job_log: str | None = Field(default=None, max_length=1_000_000)
    window_start: datetime | None = None
    limits: Limits = Limits()

    @model_validator(mode="after")
    def _check(self) -> DiagnosisInput:
        if self.mode in ("cluster", "hybrid") and self.target is None:
            raise ValueError("target is required for cluster and hybrid mode")
        if self.mode == "evidence" and not (
            self.pods or self.events or self.helm_output or self.job_log
        ):
            raise ValueError("evidence mode needs pods, events, helm_output or job_log")
        return self


class Evidence(_M):
    pods: tuple[PodEvidence, ...] = ()
    events: tuple[EventEvidence, ...] = ()
    workload: WorkloadStatus | None = None
    available: frozenset[str] = frozenset()
    partial_errors: tuple[PartialReadError, ...] = ()
    truncated: bool = False
    stale_events_suppressed: int = 0


class Finding(_M):
    rule_id: str
    sub_cause: str
    confidence: Confidence
    summary: str
    next_action: str
    evidence_refs: tuple[str, ...] = ()
    definitive: bool = False
    outcome_only: bool = False  # describes an outcome (e.g. Helm timeout), never a root cause
    causal_order: int = 50  # lower = earlier in the failure chain
    priority: int = 50
    details: dict[str, str] = Field(default_factory=dict)


class SkippedRule(_M):
    rule_id: str
    missing: tuple[str, ...]


class DiagnosisReport(_M):
    schema_version: int = SCHEMA_VERSION
    status: Status
    mode: Mode
    target: Target | None = None
    primary: Finding | None = None
    supporting: tuple[Finding, ...] = ()
    partial_errors: tuple[PartialReadError, ...] = ()
    skipped_rules: tuple[SkippedRule, ...] = ()
    rule_errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    candidates: tuple[str, ...] = ()
    stale_events_suppressed: int = 0
    truncated: bool = False
    collected_at: datetime
