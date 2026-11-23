from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
import yaml

from conftest import ctr, pod, pull_pod
from kdiag import ContainerLog, WorkloadRef
from kdiag.observability import InMemoryMetrics
from kdiag.service import (
    Deps,
    GrantAuthorizer,
    InMemoryRegistry,
    Principal,
    ServiceSettings,
    StaticAuthenticator,
    create_app,
)
from kdiag.store import SqliteStore
from kdiag.testing import FakeSource

PULL = 'Failed to pull image "registry.example.com/shop/web:2.4.1": manifest unknown'
REF = WorkloadRef(kind="Deployment", name="shop-web", namespace="shop")
SECRET_REF = WorkloadRef(kind="Deployment", name="shop-web", namespace="secret-team")

TOKENS = {
    "tok-a": Principal("alice", "tenantA", frozenset({"viewer"})),
    "tok-a2": Principal("amy", "tenantA", frozenset({"viewer"})),
    "tok-a-debug": Principal("dave", "tenantA", frozenset({"viewer", "debugger"})),
    "tok-a-admin": Principal("root", "tenantA", frozenset({"admin", "debugger", "exporter"})),
    "tok-b": Principal("bob", "tenantB", frozenset({"viewer", "exporter"})),
}
GRANTS: dict[tuple[str, str], frozenset[str] | None] = {
    ("tenantA", "prod"): None, ("tenantA", "restricted"): frozenset({"shop"}),
    ("tenantA", "nofactory"): None, ("tenantB", "prod"): None,
}
CANARY_LOG = "ModuleNotFoundError: No module named 'fastapi' password=hunter2-canary-log"


class Audit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, str]]] = []

    def record(self, event: str, **fields: str) -> None:
        self.events.append((event, fields))


@dataclass
class Env:
    app: Any
    audit: Audit
    metrics: InMemoryMetrics
    store: SqliteStore
    sources: dict[tuple[str, str], FakeSource]
    opened: list[Any] = field(default_factory=list)
    clock: list[float] = field(default_factory=lambda: [0.0])


def make_env(settings: ServiceSettings | None = None, a_delay: float = 0.0, **deps_kw: Any) -> Env:
    crash = pod("shop-web-9", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=1,
                                              restart_count=3)])
    sources = {
        ("tenantA", "prod"): FakeSource(
            [REF], pods=[pull_pod(PULL).model_copy(update={"namespace": "shop"}),
                         crash.model_copy(update={"name": "shop-web-7", "namespace": "shop"})],
            delay={"find_workloads": a_delay} if a_delay else {},
            logs=[ContainerLog(pod="shop-web-7", container="web", previous=True, lines=(CANARY_LOG,))]),
        ("tenantA", "restricted"): FakeSource([REF, SECRET_REF], pods=[pull_pod(PULL).model_copy(update={"namespace": "shop"})]),
        ("tenantA", "nofactory"): FakeSource([]),
        ("tenantB", "prod"): FakeSource([REF], pods=[crash.model_copy(update={"namespace": "shop"})]),
    }
    del sources[("tenantA", "nofactory")]
    metrics, audit, store = InMemoryMetrics(), Audit(), SqliteStore()
    env = Env(None, audit, metrics, store, sources)  # type: ignore[arg-type]
    registry = InMemoryRegistry({k: (lambda allowed, s=s: s) for k, s in sources.items()})
    deps = Deps(
        settings=settings or ServiceSettings(rate_per_s=1000, rate_burst=1000),
        authenticator=StaticAuthenticator(TOKENS), authorizer=GrantAuthorizer(GRANTS), registry=registry,
        store=store, metrics=metrics, audit=audit, clock=lambda: env.clock[0], **deps_kw)
    env.app = create_app(deps)
    return env


@asynccontextmanager
async def client(env: Env):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app, raise_app_exceptions=False), base_url="http://t") as c:
        yield c


def hdr(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


CLUSTER = {"mode": "cluster", "cluster_id": "prod", "target": {"name": "shop-web", "namespace": "shop"}}
EVIDENCE = {"mode": "evidence", "helm_output": "Error: UPGRADE FAILED: another operation (upgrade) is in progress"}


def kubeconfig_text(token: str = "CANARYKUBETOKEN123", server: str = "https://k8s.example.com:6443",
                    extra_user: dict[str, Any] | None = None) -> str:
    ca = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").decode()
    return yaml.safe_dump({
        "apiVersion": "v1", "kind": "Config", "current-context": "c",
        "contexts": [{"name": "c", "context": {"cluster": "k", "user": "u"}}],
        "clusters": [{"name": "k", "cluster": {"server": server, "certificate-authority-data": ca}}],
        "users": [{"name": "u", "user": {"token": token} | (extra_user or {})}]})


def run_all(*coros: Any) -> list[Any]:
    async def go() -> list[Any]:
        return list(await asyncio.gather(*coros))
    return asyncio.run(go())
