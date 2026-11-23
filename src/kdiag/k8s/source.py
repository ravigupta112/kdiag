"""Read-only Kubernetes EvidenceSource built on kubernetes-asyncio.

Rules this module keeps:
  * only get/list calls; there is no code path that writes;
  * never loads kubeconfig files or exec plugins (credentials come from a vetted ClusterCredentials);
  * never reads Secrets, container env, or volume data;
  * every call is rate limited, concurrency limited, counted, and audited;
  * pods are found by ownerReferences first, then selector labels, then name prefix (flagged).

An instance caches fetched workload objects, so use one instance per diagnosis.
"""
from __future__ import annotations

import asyncio
import os
import ssl
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import aiohttp
from kubernetes_asyncio import client

from ..models import (
    ContainerLog,
    EventEvidence,
    JobEvidence,
    MatchedBy,
    NodeEvidence,
    PodEvidence,
    PvcEvidence,
    ServiceEvidence,
    Target,
    WorkloadRef,
    WorkloadStatus,
)
from ..observability import NULL_AUDIT, NULL_METRICS, AuditSink, Metrics
from ..sources import SourceError
from . import convert as cv
from .kubeconfig import ClusterCredentials
from .ratelimit import TokenBucket

_EVENT_KINDS = {"Deployment", "ReplicaSet", "StatefulSet", "Pod", "PersistentVolumeClaim", "Job", "CronJob"}
_PAGE = 500


@dataclass
class K8sApis:
    core: Any
    apps: Any
    batch: Any
    discovery: Any


def map_exception(exc: BaseException) -> SourceError:
    """Map SDK/network errors to SourceError. Messages are generic: exception text may hold secrets."""
    if isinstance(exc, client.ApiException):
        st = exc.status or 0
        if st in (401, 403):
            return SourceError("forbidden", f"HTTP {st}")
        if st == 404:
            return SourceError("not_found", "HTTP 404")
        if st == 429:
            return SourceError("rate_limited", "HTTP 429", retryable=True)
        return SourceError("error", f"HTTP {st}", retryable=st >= 500)
    if isinstance(exc, aiohttp.ClientError | ssl.SSLError | ConnectionError | OSError):
        return SourceError("unreachable", "connection failed", retryable=True)
    return SourceError("error", "unexpected error")


def _retry_after(exc: BaseException) -> float | None:
    headers = getattr(exc, "headers", None)
    try:
        raw = headers.get("Retry-After") if headers else None
        return float(raw) if raw is not None else None
    except (TypeError, ValueError, AttributeError):
        return None


def _selector(match_labels: dict[str, str] | None) -> str | None:
    if not match_labels:
        return None
    return ",".join(f"{k}={v}" for k, v in sorted(match_labels.items()))


def _owned_by(obj: Any, uids: set[str]) -> bool:
    return any(r.uid in uids for r in (obj.metadata.owner_references or []))


class KubernetesSource:
    def __init__(
        self,
        apis: K8sApis,
        *,
        allowed_namespaces: frozenset[str] | None = None,
        limiter: TokenBucket | None = None,
        concurrency: int = 8,
        metrics: Metrics | None = None,
        audit: AuditSink | None = None,
        namespace_search_limit: int = 200,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._a = apis
        self._allowed = allowed_namespaces
        self._limiter = limiter
        self._sem = asyncio.Semaphore(concurrency)
        self._metrics = metrics or NULL_METRICS
        self._audit = audit or NULL_AUDIT
        self._ns_limit = namespace_search_limit
        self._sleep = sleep
        self._objs: dict[tuple[str, str, str], Any] = {}
        self._related_names: set[str] = set()

    # ---- plumbing ----------------------------------------------------------------------------

    def _check_ns(self, ns: str) -> None:
        if self._allowed is not None and ns not in self._allowed:
            raise SourceError("forbidden", "namespace not permitted")

    async def _api(self, api: Any, op: str, resource: str, namespace: str | None,
                   *args: Any, **kw: Any) -> Any:
        if namespace is not None:
            self._check_ns(namespace)
        for attempt in (0, 1):
            async with self._sem:
                if self._limiter:
                    await self._limiter.acquire()
                self._metrics.inc("kdiag_k8s_api_calls_total", resource=resource,
                                  verb="get" if op.startswith("read") else "list")
                self._audit.record("k8s.read", resource=resource, namespace=namespace or "",
                                   op=op)
                try:
                    return await getattr(api, op)(*args, **kw)
                except TimeoutError:
                    raise
                except Exception as exc:  # noqa: BLE001 - mapped below; text never propagates
                    mapped = map_exception(exc)
                    self._metrics.inc("kdiag_k8s_api_errors_total", resource=resource,
                                      reason=mapped.reason)
                    wait = _retry_after(exc) if mapped.reason == "rate_limited" else None
                    if attempt == 0 and wait is not None and wait <= 2.0:
                        pass  # fall through to retry once after sleeping (outside the semaphore)
                    else:
                        raise mapped from None
            await self._sleep(wait or 0)
        raise SourceError("rate_limited", "HTTP 429", retryable=True)  # pragma: no cover

    async def _paged(self, api: Any, op: str, resource: str, namespace: str | None, limit: int,
                     **kw: Any) -> list[Any]:
        items: list[Any] = []
        token: str | None = None
        while len(items) < limit:
            page_kw = dict(kw, limit=max(1, min(_PAGE, limit - len(items))))
            if token:
                page_kw["_continue"] = token
            args = (namespace,) if namespace is not None else ()
            page = await self._api(api, op, resource, namespace, *args, **page_kw)
            items.extend(page.items or [])
            token = getattr(page.metadata, "_continue", None) if page.metadata else None
            if not token:
                break
        return items[:limit]

    def _read_op(self, kind: str) -> tuple[Any, str]:
        return {
            "Deployment": (self._a.apps, "read_namespaced_deployment"),
            "StatefulSet": (self._a.apps, "read_namespaced_stateful_set"),
            "Job": (self._a.batch, "read_namespaced_job"),
            "CronJob": (self._a.batch, "read_namespaced_cron_job"),
        }[kind]

    async def _workload(self, ref: WorkloadRef) -> Any:
        key = (ref.kind, ref.namespace, ref.name)
        if key not in self._objs:
            api, op = self._read_op(ref.kind)
            self._objs[key] = await self._api(api, op, ref.kind.lower(), ref.namespace,
                                              ref.name, ref.namespace)
        return self._objs[key]

    # ---- EvidenceSource ----------------------------------------------------------------------

    async def _candidate_namespaces(self) -> list[str]:
        if self._allowed is not None:
            return sorted(self._allowed)[: self._ns_limit]
        try:
            items = await self._paged(self._a.core, "list_namespace", "namespaces", None, self._ns_limit)
        except SourceError as exc:
            if exc.reason == "forbidden":
                raise SourceError("forbidden", "namespace not given and namespaces cannot be listed") from None
            raise
        return sorted(n.metadata.name for n in items)

    async def find_workloads(self, target: Target) -> list[WorkloadRef]:
        namespaces = [target.namespace] if target.namespace else await self._candidate_namespaces()

        async def probe(ns: str) -> WorkloadRef | None:
            ref = WorkloadRef(kind=target.kind, name=target.name, namespace=ns)
            try:
                await self._workload(ref)
            except SourceError as exc:
                if exc.reason == "not_found":
                    return None
                raise
            return ref

        results = await asyncio.gather(*(probe(ns) for ns in namespaces), return_exceptions=True)
        refs = [r for r in results if isinstance(r, WorkloadRef)]
        errors = [r for r in results if isinstance(r, BaseException)]
        if errors and (not refs or target.namespace):
            raise errors[0]
        return sorted(refs, key=lambda r: r.namespace)

    async def get_workload_status(self, ref: WorkloadRef) -> WorkloadStatus:
        if ref.kind in ("Job", "CronJob"):
            return WorkloadStatus()  # rollout status does not apply; job state comes from list_jobs
        return cv.workload_status_from_v1(await self._workload(ref))

    async def _pods_for_job(self, ns: str, job: Any, limit: int) -> list[PodEvidence]:
        pods = await self._paged(self._a.core, "list_namespaced_pod", "pods", ns, limit,
                                 label_selector=f"job-name={job.metadata.name}")
        uid = {job.metadata.uid}
        return [cv.pod_from_v1(p, "owner") for p in pods if _owned_by(p, uid)]

    async def _owned_jobs(self, ref: WorkloadRef, newest: int = 3) -> list[Any]:
        cj = await self._workload(ref)
        jobs = await self._paged(self._a.batch, "list_namespaced_job", "jobs", ref.namespace, 200)
        owned = [j for j in jobs if _owned_by(j, {cj.metadata.uid})]
        owned.sort(key=lambda j: str(j.metadata.creation_timestamp), reverse=True)
        return owned[:newest]

    async def list_pods(self, ref: WorkloadRef, limit: int) -> list[PodEvidence]:
        ns, obj = ref.namespace, await self._workload(ref)
        found: list[PodEvidence] = []
        if ref.kind == "Job":
            found = await self._pods_for_job(ns, obj, limit)
        elif ref.kind == "CronJob":
            for job in await self._owned_jobs(ref):
                found += await self._pods_for_job(ns, job, limit)
        else:
            sel = _selector(getattr(obj.spec.selector, "match_labels", None))
            uids = {obj.metadata.uid}
            if ref.kind == "Deployment":
                sets = await self._paged(self._a.apps, "list_namespaced_replica_set", "replicasets",
                                         ns, 200, **({"label_selector": sel} if sel else {}))
                owned = [rs for rs in sets if _owned_by(rs, {obj.metadata.uid})]
                self._related_names |= {rs.metadata.name for rs in owned}
                uids = {rs.metadata.uid for rs in owned}
            kw = {"label_selector": sel} if sel else {}
            pods = await self._paged(self._a.core, "list_namespaced_pod", "pods", ns, limit, **kw)
            found = [cv.pod_from_v1(p, "owner") for p in pods if _owned_by(p, uids)]
            if not found and pods:  # selector matched pods that nothing owns: weaker evidence
                found = [cv.pod_from_v1(p, "selector") for p in pods]
        if not found:  # last resort: name prefix, clearly flagged
            pods = await self._paged(self._a.core, "list_namespaced_pod", "pods", ns, limit)
            prefix = ref.name + "-"
            by: MatchedBy = "name"
            found = [cv.pod_from_v1(p, by) for p in pods if p.metadata.name.startswith(prefix)]
        found.sort(key=lambda p: p.name)
        self._related_names |= {c for p in found for c in p.pvc_claims}
        return found[:limit]

    async def list_events(
        self, ref: WorkloadRef, pod_names: Sequence[str], limit: int
    ) -> list[EventEvidence]:
        names = {ref.name, *pod_names, *self._related_names}
        raw = await self._paged(self._a.core, "list_namespaced_event", "events", ref.namespace,
                                limit * 5)
        out = [cv.event_from_v1(e) for e in raw
               if e.involved_object and e.involved_object.name in names
               and e.involved_object.kind in _EVENT_KINDS]
        return out[:limit]

    async def get_nodes(self, names: Sequence[str]) -> list[NodeEvidence]:
        async def one(n: str) -> NodeEvidence | None:
            try:
                return cv.node_from_v1(await self._api(self._a.core, "read_node", "nodes", None, n))
            except SourceError as exc:
                if exc.reason == "not_found":
                    return None
                raise

        results = await asyncio.gather(*(one(n) for n in list(names)[:50]), return_exceptions=True)
        ok = [r for r in results if isinstance(r, NodeEvidence)]
        bad = [r for r in results if isinstance(r, BaseException)]
        if bad and not ok:
            raise bad[0]
        return ok

    async def list_pvcs(self, ref: WorkloadRef, names: Sequence[str]) -> list[PvcEvidence]:
        async def one(n: str) -> PvcEvidence | None:
            try:
                obj = await self._api(self._a.core, "read_namespaced_persistent_volume_claim",
                                      "pvcs", ref.namespace, n, ref.namespace)
                return cv.pvc_from_v1(obj)
            except SourceError as exc:
                if exc.reason == "not_found":
                    return None
                raise

        results = await asyncio.gather(*(one(n) for n in list(names)[:50]), return_exceptions=True)
        ok = [r for r in results if isinstance(r, PvcEvidence)]
        bad = [r for r in results if isinstance(r, BaseException)]
        if bad and not ok:
            raise bad[0]
        return ok

    async def list_services(
        self, ref: WorkloadRef, pods: Sequence[PodEvidence]
    ) -> list[ServiceEvidence]:
        svcs = await self._paged(self._a.core, "list_namespaced_service", "services", ref.namespace, _PAGE)
        slices = await self._paged(self._a.discovery, "list_namespaced_endpoint_slice",
                                   "endpointslices", ref.namespace, _PAGE)
        by_svc: dict[str, list[Any]] = {}
        for sl in slices:
            name = (sl.metadata.labels or {}).get("kubernetes.io/service-name")
            if name:
                by_svc.setdefault(name, []).append(sl)
        instances = {p.labels.get("app.kubernetes.io/instance") for p in pods} - {None}
        pod_labels = [set(p.labels.items()) for p in pods]
        out: list[ServiceEvidence] = []
        for s in svcs:
            selector = dict(s.spec.selector or {})
            related: str | None = None
            if s.metadata.name == ref.name:
                related = "name"
            elif (s.metadata.labels or {}).get("app.kubernetes.io/instance") in instances:
                related = "label"
            elif selector and any(set(selector.items()) & pl for pl in pod_labels):
                related = "selector"
            if related is None:
                continue
            ready, not_ready = cv.endpoint_counts(by_svc.get(s.metadata.name, []))
            out.append(ServiceEvidence(
                name=s.metadata.name, namespace=ref.namespace, selector=cv._labels(selector),
                ready_endpoints=ready, not_ready_endpoints=not_ready,
                related_by=related,
            ))
        return sorted(out, key=lambda s: s.name)[:50]

    async def list_jobs(self, ref: WorkloadRef) -> list[JobEvidence]:
        if ref.kind == "Job":
            return [cv.job_from_v1(await self._workload(ref))]
        return [cv.job_from_v1(j) for j in await self._owned_jobs(ref)]

    async def get_namespace_phase(self, namespace: str) -> str:
        ns = await self._api(self._a.core, "read_namespace", "namespaces", namespace, namespace)
        return str(ns.status.phase or "Unknown")

    async def get_logs(
        self, ref: WorkloadRef, pod: str, container: str, previous: bool,
        tail_lines: int, limit_bytes: int,
    ) -> ContainerLog:
        self._audit.record("k8s.read_logs", namespace=ref.namespace, pod=pod, container=container)
        try:
            text = await self._api(
                self._a.core, "read_namespaced_pod_log", "pod_logs", ref.namespace, pod, ref.namespace,
                container=container, previous=previous, tail_lines=tail_lines, limit_bytes=limit_bytes)
        except SourceError as exc:
            if exc.detail == "HTTP 400":  # container never started / no previous instance
                raise SourceError("not_found") from None
            raise
        lines = tuple(line[:4000] for line in str(text or "").splitlines()[-tail_lines:])
        return ContainerLog(pod=pod, container=container, previous=previous, lines=lines)

    # ---- construction ------------------------------------------------------------------------

    @classmethod
    @asynccontextmanager
    async def connect(cls, creds: ClusterCredentials, **kw: Any) -> AsyncIterator[KubernetesSource]:
        """Build a source from vetted credentials. TLS verification is always on; the bearer token is
        held in memory only. The CA bundle (public data) is written to a private temp file because the
        SDK requires a path, and removed on exit."""
        cfg = client.Configuration()
        cfg.host = creds.server
        cfg.verify_ssl = True
        cfg.api_key = {"BearerToken": creds.token}
        cfg.api_key_prefix = {"BearerToken": "Bearer"}
        tmp_path: str | None = None
        if creds.ca_pem:
            fd, tmp_path = tempfile.mkstemp(suffix=".pem")
            with os.fdopen(fd, "w") as fh:
                fh.write(creds.ca_pem)
            cfg.ssl_ca_cert = tmp_path
        api = client.ApiClient(cfg)
        try:
            yield cls(K8sApis(client.CoreV1Api(api), client.AppsV1Api(api), client.BatchV1Api(api),
                              client.DiscoveryV1Api(api)), **kw)
        finally:
            await api.close()
            if tmp_path:
                os.unlink(tmp_path)
