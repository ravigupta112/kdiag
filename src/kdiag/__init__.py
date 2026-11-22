"""kdiag: deterministic, read-only Kubernetes deployment failure diagnosis."""
from .engine import diagnose
from .models import (
    SCHEMA_VERSION,
    Condition,
    ContainerEvidence,
    DiagnosisInput,
    DiagnosisReport,
    EventEvidence,
    Finding,
    Limits,
    PartialReadError,
    PodEvidence,
    Target,
    WorkloadRef,
    WorkloadStatus,
)
from .render import render_text
from .sources import EvidenceSource, SourceError

__all__ = [
    "SCHEMA_VERSION",
    "Condition",
    "ContainerEvidence",
    "DiagnosisInput",
    "DiagnosisReport",
    "EventEvidence",
    "EvidenceSource",
    "Finding",
    "Limits",
    "PartialReadError",
    "PodEvidence",
    "SourceError",
    "Target",
    "WorkloadRef",
    "WorkloadStatus",
    "diagnose",
    "render_text",
]
