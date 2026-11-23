"""HTTP API. Authorization, rate limiting, backpressure and size limits are enforced here, on the
server. The library underneath stays framework-free; this layer is optional (`kdiag[service]`)."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from ..engine import diagnose
from ..export import ConsentRequired, ExportBlocked, ExportOptions, build_prompt
from ..k8s.kubeconfig import ClusterCredentials, KubeconfigRejected, parse_kubeconfig
from ..models import (
    ContainerLog,
    DiagnosisInput,
    DiagnosisReport,
    DnsLabel,
    DnsSubdomain,
    EventEvidence,
    JobEvidence,
    Mode,
    Name,
    NodeEvidence,
    PodEvidence,
    PvcEvidence,
    ServiceEvidence,
    Target,
    WorkloadStatus,
)
from ..observability import NULL_AUDIT, NULL_METRICS, AuditSink, Metrics
from ..sources import EvidenceSource
from ..store import SqliteStore
from .auth import Authenticator, Authorizer, Principal
from .cache import TTLCache, cache_key
from .registry import ClusterRegistry, UnknownCluster
from .settings import ServiceSettings

log = logging.getLogger("kdiag.service")
ADHOC = "adhoc"  # history label for evidence-mode and uploaded-kubeconfig runs; not a registered cluster
JobId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
OpenCredentials = Callable[[ClusterCredentials, frozenset[str] | None],
                           AbstractAsyncContextManager[EvidenceSource]]


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acknowledge_external_sharing: bool = False
    max_chars: int | None = Field(default=None, ge=500, le=50_000)


class DiagnoseRequest(BaseModel):
    """What a client may send. Limits, tenant and authorization are deliberately absent."""

    model_config = ConfigDict(extra="forbid")
    mode: Mode
    cluster_id: Name | None = None
    target: Target | None = None
    namespace: DnsLabel | None = None
    release: DnsSubdomain | None = None
    pods: tuple[PodEvidence, ...] = Field(default=(), max_length=500)
    events: tuple[EventEvidence, ...] = Field(default=(), max_length=5000)
    nodes: tuple[NodeEvidence, ...] = Field(default=(), max_length=100)
    pvcs: tuple[PvcEvidence, ...] = Field(default=(), max_length=100)
    services: tuple[ServiceEvidence, ...] = Field(default=(), max_length=100)
    jobs: tuple[JobEvidence, ...] = Field(default=(), max_length=50)
    logs: tuple[ContainerLog, ...] = Field(default=(), max_length=100)
    namespace_phase: Name | None = None
    workload_status: WorkloadStatus | None = None
    helm_output: str | None = Field(default=None, max_length=1_000_000)
    job_log: str | None = Field(default=None, max_length=1_000_000)
    window_start: datetime | None = None
    include_logs: bool = False
    job_id: JobId | None = None
    save: bool = False
    refresh: bool = False
    kubeconfig: str | None = Field(default=None, max_length=262_144)
    export: ExportRequest | None = None


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None,
                 extra: dict[str, Any] | None = None) -> None:
        super().__init__(code)
        self.status, self.code, self.message = status, code, message
        self.headers, self.extra = headers or {}, extra


@dataclass
class Deps:
    settings: ServiceSettings
    authenticator: Authenticator
    authorizer: Authorizer
    registry: ClusterRegistry
    store: SqliteStore | None = None
    metrics: Metrics = NULL_METRICS
    audit: AuditSink = NULL_AUDIT
    open_credentials: OpenCredentials | None = None
    cache: TTLCache | None = None
    clock: Callable[[], float] | None = None
    _extra: dict[str, Any] = field(default_factory=dict)


def _safe_errors(exc: RequestValidationError | ValidationError) -> list[dict[str, Any]]:
    """Field path + message only. Pydantic's `input`/`ctx` are dropped: they can echo secrets."""
    return [{"loc": [str(x) for x in e.get("loc", ())], "msg": str(e.get("msg", "invalid")),
             "type": str(e.get("type", "invalid"))} for e in exc.errors()]


def _default_open_credentials(creds: ClusterCredentials, allowed: frozenset[str] | None) -> AbstractAsyncContextManager[EvidenceSource]:
    from ..k8s.source import KubernetesSource

    return KubernetesSource.connect(creds, allowed_namespaces=allowed)


def create_app(deps: Deps) -> FastAPI:
    s = deps.settings
    m, audit = deps.metrics, deps.audit
    cache = deps.cache or TTLCache(s.cache_max_entries, s.cache_ttl_s, s.cache_max_bytes,
                                   **({"clock": deps.clock} if deps.clock else {}))
    open_creds = deps.open_credentials or _default_open_credentials
    sem = asyncio.Semaphore(s.max_concurrent)
    inflight: dict[tuple[str, ...], asyncio.Future[DiagnosisReport]] = {}
    buckets: OrderedDict[str, Any] = OrderedDict()
    app = FastAPI(title="kdiag", docs_url=None, redoc_url=None, openapi_url=None)

    # ---- plumbing ----------------------------------------------------------------------------

    def envelope(request: Request, status: int, *, report: DiagnosisReport | None = None,
                 error: tuple[str, str] | None = None, meta: dict[str, Any] | None = None,
                 extra: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> JSONResponse:
        body: dict[str, Any] = {
            "report": report.model_dump(mode="json") if report else None,
            "error": {"code": error[0], "message": error[1]} if error else None,
            "meta": {"request_id": getattr(request.state, "request_id", ""), **(meta or {})},
        }
        body.update(extra or {})
        return JSONResponse(body, status_code=status, headers=headers)

    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable[[Request], Awaitable[Any]]) -> Any:
        request.state.request_id = uuid.uuid4().hex
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > s.max_body_bytes:
            resp = envelope(request, 413, error=("too_large", "Request body is too large"))
        else:
            resp = await call_next(request)
        route = request.scope.get("route")
        m.inc("kdiag_http_requests_total", route=getattr(route, "path", "unmatched"), code=str(resp.status_code))
        resp.headers["X-Request-ID"] = request.state.request_id
        return resp

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return envelope(request, exc.status, error=(exc.code, exc.message), headers=exc.headers,
                        extra=exc.extra)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return envelope(request, 422, error=("invalid_request", "The request is invalid"),
                        extra={"details": _safe_errors(exc)})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error: %s", type(exc).__name__)  # type only: text may carry credentials
        return envelope(request, 500, error=("internal", "Internal error"))

    def require_enabled() -> None:
        if not s.enabled:
            raise ApiError(404, "disabled", "Not found")

    async def principal(request: Request) -> Principal:
        p = await deps.authenticator.authenticate(request)
        if p is None:
            raise ApiError(401, "unauthenticated", "Authentication required", {"WWW-Authenticate": "Bearer"})
        return p

    def rate_limit(p: Principal) -> None:
        from ..k8s.ratelimit import TokenBucket

        key = f"{p.tenant_id}/{p.user_id}"
        b = buckets.get(key)
        if b is None:
            b = buckets[key] = TokenBucket(s.rate_per_s, s.rate_burst)
            while len(buckets) > 10_000:
                buckets.popitem(last=False)
        buckets.move_to_end(key)
        wait = b.try_acquire()
        if wait > 0:
            m.inc("kdiag_rate_limited_total")
            raise ApiError(429, "rate_limited", "Too many requests", {"Retry-After": str(max(1, math.ceil(wait)))})

    @asynccontextmanager
    async def gate() -> AsyncIterator[None]:
        try:
            await asyncio.wait_for(sem.acquire(), s.queue_wait_s)
        except TimeoutError:
            m.inc("kdiag_backpressure_total")
            raise ApiError(503, "busy", "The service is busy; retry shortly", {"Retry-After": "2"}) from None
        try:
            yield
        finally:
            sem.release()

    async def may_view(p: Principal, cluster_id: str) -> bool:
        """Ad-hoc reports belong to the tenant that made them (the store is tenant-scoped);
        registered clusters need an explicit grant."""
        return cluster_id == ADHOC or await deps.authorizer.can_view_history(p, cluster_id)

    def build_export(report: DiagnosisReport, req: ExportRequest) -> dict[str, Any]:
        opts = ExportOptions(consent=req.acknowledge_external_sharing,
                             max_chars=req.max_chars or s.export_max_chars)
        res = build_prompt(report, opts)
        m.inc("kdiag_prompt_exports_total", result="ok")
        return {"text": res.text, "metadata": res.metadata.model_dump(mode="json")}

    # ---- routes ------------------------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/v1/diagnose")
    async def diagnose_route(request: Request, body: DiagnoseRequest) -> JSONResponse:
        require_enabled()
        p = await principal(request)
        rate_limit(p)

        if body.export and not body.export.acknowledge_external_sharing:
            raise ApiError(400, "consent_required", "Acknowledge that the prompt will be shared externally")
        if body.export and not await deps.authorizer.can_export(p):
            raise ApiError(403, "forbidden", "Not permitted")
        if body.include_logs and not await deps.authorizer.can_debug(p):
            raise ApiError(403, "debug_not_permitted", "Container logs need debug authorization")

        visible: frozenset[str] | None = None
        creds: ClusterCredentials | None = None
        if body.cluster_id == ADHOC:
            raise ApiError(422, "invalid_request", "cluster_id 'adhoc' is reserved")
        cluster_label = body.cluster_id or ADHOC
        if body.mode != "evidence":
            if body.kubeconfig and body.cluster_id:
                raise ApiError(422, "invalid_request", "Send either cluster_id or kubeconfig, not both")
            if body.kubeconfig:
                if not s.allow_kubeconfig_upload or not await deps.authorizer.can_upload_kubeconfig(p):
                    raise ApiError(403, "upload_not_permitted", "Kubeconfig upload is not permitted")
                try:
                    creds = await parse_kubeconfig(
                        body.kubeconfig, allowed_hosts=s.kubeconfig_allowed_hosts,
                        allow_private=s.kubeconfig_allow_private)
                except KubeconfigRejected as exc:
                    m.inc("kdiag_kubeconfig_rejected_total", code=exc.code)
                    raise ApiError(422, exc.code, exc.message) from None
            elif body.cluster_id:
                visible = await deps.authorizer.visible_namespaces(p, body.cluster_id)
                ns = body.target.namespace if body.target else None
                if visible is not None and (not visible or (ns is not None and ns not in visible)):
                    raise ApiError(403, "forbidden", "Not permitted")
            else:
                raise ApiError(422, "invalid_request", "cluster_id is required for cluster and hybrid mode")
        body_kubeconfig_present = creds is not None

        try:
            inp = DiagnosisInput(
                mode=body.mode, cluster_id=body.cluster_id, target=body.target, namespace=body.namespace,
                release=body.release, pods=body.pods, events=body.events, nodes=body.nodes, pvcs=body.pvcs,
                services=body.services, jobs=body.jobs, logs=body.logs, namespace_phase=body.namespace_phase,
                workload_status=body.workload_status, collect_logs=body.include_logs,
                helm_output=body.helm_output, job_log=body.job_log, window_start=body.window_start,
                limits=s.limits)
        except ValidationError as exc:
            raise ApiError(422, "invalid_request", "The request is invalid",
                           extra={"details": _safe_errors(exc)}) from None

        async def compute() -> DiagnosisReport:
            if body.mode == "evidence":
                return await diagnose(inp, None, metrics=m)
            ctx = (open_creds(creds, None) if creds is not None
                   else deps.registry.open(p.tenant_id, body.cluster_id or "", visible))
            async with ctx as src:
                return await diagnose(inp, src, metrics=m)

        cached: bool | str = False
        key = None
        if body.mode != "evidence" and body.cluster_id and not body_kubeconfig_present and body.target:
            scope = "all" if visible is None else hashlib.sha256(",".join(sorted(visible)).encode()).hexdigest()[:16]
            key = cache_key(p.tenant_id, body.cluster_id, body.target.namespace, body.target.kind,
                            body.target.name, body.job_id, body.include_logs, scope)
        try:
            report: DiagnosisReport | None = None
            if key is not None and not body.refresh and (hit := cache.get(key)) is not None:
                report, cached = hit, True
                m.inc("kdiag_cache_total", result="hit")
            else:
                async with gate():
                    if key is not None and (pending := inflight.get(key)) is not None and not body.refresh:
                        report, cached = await asyncio.shield(pending), "coalesced"
                        m.inc("kdiag_cache_total", result="coalesced")
                    else:
                        if key is not None:
                            m.inc("kdiag_cache_total", result="miss")
                            fut: asyncio.Future[DiagnosisReport] = asyncio.get_running_loop().create_future()
                            fut.add_done_callback(lambda f: f.cancelled() or f.exception())
                            inflight[key] = fut
                        try:
                            report = await compute()
                            if key is not None:
                                cache.set(key, report)
                                fut.set_result(report)
                        except BaseException as exc:
                            if key is not None and not fut.done():
                                fut.set_exception(exc if isinstance(exc, Exception) else RuntimeError("cancelled"))
                            raise
                        finally:
                            if key is not None:
                                inflight.pop(key, None)
        except UnknownCluster:
            raise ApiError(404, "cluster_not_found", "Cluster not found") from None

        assert report is not None
        meta: dict[str, Any] = {"cached": cached, "saved": False, "report_id": None}
        audit.record("diagnose", tenant=p.tenant_id, user=p.user_id, cluster=cluster_label,
                     namespace=(body.target.namespace or "") if body.target else "",
                     target=body.target.name if body.target else "", status=report.status, mode=body.mode)

        if s.shadow_mode:
            return envelope(request, 202, meta={"shadow": True})

        if body.save and deps.store is not None:
            try:
                saved = await deps.store.save(p.tenant_id, cluster_label, report, job_id=body.job_id)
                meta.update(saved=True, report_id=saved.id, save_action=saved.action)
            except Exception as exc:  # noqa: BLE001 - history is best-effort; never fail the diagnosis
                meta["save_error"] = type(exc).__name__

        extra: dict[str, Any] = {}
        if body.export:
            try:
                extra["prompt"] = build_export(report, body.export)
                audit.record("export", tenant=p.tenant_id, user=p.user_id,
                             sha256=extra["prompt"]["metadata"]["sha256"])
            except ExportBlocked:
                m.inc("kdiag_prompt_exports_total", result="blocked")
                meta["export_error"] = "export_blocked"

        status, error = 200, None
        if report.status == "target_not_found":
            status, error = 404, ("target_not_found", "No matching workload was found in the searched scope")
        elif report.status == "cluster_unreachable":
            timed_out = any(e.reason == "timeout" for e in report.partial_errors)
            status, error = (504 if timed_out else 502), ("cluster_unreachable", "The cluster could not be reached; retry")
        return envelope(request, status, report=report, error=error, meta=meta, extra=extra)

    @app.get("/v1/reports/{report_id}")
    async def get_report(request: Request, report_id: str) -> JSONResponse:
        require_enabled()
        p = await principal(request)
        rate_limit(p)
        if deps.store is None:
            raise ApiError(501, "history_disabled", "History is not enabled")
        stored = await deps.store.get(p.tenant_id, report_id[:64])  # tenant comes from auth, never the URL
        if stored is None or not await may_view(p, stored.summary.cluster_id):
            raise ApiError(404, "not_found", "Report not found")  # same answer for 'missing' and 'not yours'
        meta = {"report_id": stored.summary.id, "created_at": stored.summary.created_at,
                "updated_at": stored.summary.updated_at, "history": stored.history}
        if stored.unreadable:
            meta["unreadable"] = stored.unreadable
        return envelope(request, 200, report=stored.report, meta=meta)

    @app.get("/v1/reports")
    async def list_reports(request: Request, cluster_id: str, name: str, namespace: str | None = None,
                           limit: int = 20) -> JSONResponse:
        require_enabled()
        p = await principal(request)
        rate_limit(p)
        if deps.store is None:
            raise ApiError(501, "history_disabled", "History is not enabled")
        if not await may_view(p, cluster_id):
            raise ApiError(403, "forbidden", "Not permitted")
        visible = (None if cluster_id == ADHOC
                   else await deps.authorizer.visible_namespaces(p, cluster_id))
        if namespace is not None and visible is not None and namespace not in visible:
            raise ApiError(403, "forbidden", "Not permitted")
        rows = await deps.store.list_for_target(p.tenant_id, cluster_id, namespace, name, limit)
        rows = [r for r in rows if visible is None or (r.namespace in visible)]
        return envelope(request, 200, extra={"reports": [r.__dict__ for r in rows]})

    @app.post("/v1/reports/{report_id}/export")
    async def export_report(request: Request, report_id: str, body: ExportRequest) -> JSONResponse:
        require_enabled()
        p = await principal(request)
        rate_limit(p)
        if deps.store is None:
            raise ApiError(501, "history_disabled", "History is not enabled")
        if not await deps.authorizer.can_export(p):
            raise ApiError(403, "forbidden", "Not permitted")
        stored = await deps.store.get(p.tenant_id, report_id[:64])
        if stored is None or not await may_view(p, stored.summary.cluster_id):
            raise ApiError(404, "not_found", "Report not found")
        if stored.report is None:
            raise ApiError(409, "report_unreadable", "The stored report cannot be read")
        try:
            prompt = build_export(stored.report, body)
        except ConsentRequired:
            raise ApiError(400, "consent_required", "Acknowledge that the prompt will be shared externally") from None
        except ExportBlocked:
            m.inc("kdiag_prompt_exports_total", result="blocked")
            raise ApiError(409, "export_blocked", "The export was blocked because it looked sensitive") from None
        audit.record("export", tenant=p.tenant_id, user=p.user_id, report=stored.summary.id,
                     sha256=prompt["metadata"]["sha256"])
        return envelope(request, 200, extra={"prompt": prompt})

    return app
