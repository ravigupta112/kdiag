"""kdiag: deterministic, read-only Kubernetes deployment failure diagnosis."""
from .engine import diagnose
from .export import (
    ConsentRequired,
    ExportBlocked,
    ExportMetadata,
    ExportOptions,
    ExportResult,
    build_prompt,
)
from .models import (
    SCHEMA_VERSION,
    Condition,
    ContainerEvidence,
    ContainerLog,
    DiagnosisInput,
    DiagnosisReport,
    EventEvidence,
    Finding,
    JobEvidence,
    Limits,
    NodeEvidence,
    PartialReadError,
    PodEvidence,
    PvcEvidence,
    ServiceEvidence,
    Target,
    WorkloadRef,
    WorkloadStatus,
)
from .observability import InMemoryMetrics, Metrics, NullMetrics
from .render import render_text
from .sources import EvidenceSource, SourceError

__all__ = [
    "SCHEMA_VERSION", "Condition", "ConsentRequired", "ContainerEvidence", "ContainerLog",
    "DiagnosisInput", "DiagnosisReport", "EventEvidence", "EvidenceSource", "ExportBlocked",
    "ExportMetadata", "ExportOptions", "ExportResult", "Finding", "InMemoryMetrics", "JobEvidence",
    "Limits", "Metrics", "NodeEvidence", "NullMetrics", "PartialReadError", "PodEvidence",
    "PvcEvidence", "ServiceEvidence", "SourceError", "Target", "WorkloadRef", "WorkloadStatus",
    "build_prompt", "diagnose", "render_text",
]
