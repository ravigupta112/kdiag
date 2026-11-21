"""Typed contracts. Frozen, extra-forbidden, versioned.

Deliberately absent: Secret values, env values, tokens, kubeconfigs. Pod env is
never modelled; a test asserts no field name hints at credential content.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class _M(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Target(_M):
    kind: WorkloadKind = "Deployment"
    name: str = Field(min_length=1, max_length=253)
    namespace: str | None = Field(default=None, max_length=63)


class WorkloadRef(_M):
    kind: WorkloadKind
    name: str
    namespace: str


class Condition(_M):
    type: str
    status: str
    reason: str | None = None
    message: str | None = None


class ContainerEvidence(_M):
    name: str
    is_init: bool = False
    ready: bool = False
    restart_count: int = 0
    waiting_reason: str | None = None
    waiting_message: str | None = None
    terminated_reason: str | None = None
    terminated_exit_code: int | None = None
    last_terminated_reason: str | None = None
    last_exit_code: int | None = None
    memory_limit: str | None = None


class PodEvidence(_M):
    name: str
    namespace: str
    phase: str = "Unknown"
    node_name: str | None = None
    conditions: tuple[Condition, ...] = ()
    containers: tuple[ContainerEvidence, ...] = ()


class EventEvidence(_M):
    object_kind: str
    object_name: str
    type: str = "Normal"
    reason: str = ""
    message: str = ""
    timestamp: datetime | None = None
    count: int = 1
    time_unknown: bool = False


class PartialReadError(_M):
    resource: str
    reason: ReadFailure
    retryable: bool = False
    detail: str | None = None


class Limits(_M):
    max_pods: int = Field(default=50, ge=0)  # pods analysed
    max_events: int = Field(default=500, ge=0)  # events analysed
    max_pods_fetched: int = Field(default=500, ge=0)  # hard ceiling on what the source may return
    max_events_fetched: int = Field(default=2000, ge=0)
    concurrency: int = Field(default=8, ge=1)
    request_timeout_s: float = Field(default=5.0, gt=0)
    overall_timeout_s: float = Field(default=30.0, gt=0)
    max_report_bytes: int = Field(default=262_144, ge=1)


class DiagnosisInput(_M):
    mode: Mode
    cluster_id: str | None = None
    target: Target | None = None
    namespace: str | None = None
    release: str | None = None
    pods: tuple[PodEvidence, ...] = ()
    events: tuple[EventEvidence, ...] = ()
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
    candidates: tuple[str, ...] = ()
    stale_events_suppressed: int = 0
    truncated: bool = False
    collected_at: datetime
