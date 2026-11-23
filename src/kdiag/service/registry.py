from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Protocol

from ..sources import EvidenceSource


class UnknownCluster(Exception):
    pass


class ClusterRegistry(Protocol):
    def open(self, tenant_id: str, cluster_id: str,
             allowed_namespaces: frozenset[str] | None) -> AbstractAsyncContextManager[EvidenceSource]:
        """Yield a read-only source for this tenant's cluster, or raise UnknownCluster."""
        ...


class InMemoryRegistry:
    """Tests and examples: factories keyed by (tenant, cluster). Another tenant's id is 'unknown'."""

    def __init__(self, factories: dict[tuple[str, str], Callable[[frozenset[str] | None], EvidenceSource]]) -> None:
        self._f = dict(factories)

    @asynccontextmanager
    async def open(self, tenant_id: str, cluster_id: str,
                   allowed_namespaces: frozenset[str] | None) -> AsyncIterator[EvidenceSource]:
        factory = self._f.get((tenant_id, cluster_id))
        if factory is None:
            raise UnknownCluster(cluster_id)
        yield factory(allowed_namespaces)


class KubernetesRegistry:
    """Production registry: resolves stored per-tenant credentials, then connects read-only."""

    def __init__(self, credentials: Callable[[str, str], Awaitable[Any | None]], **source_kw: Any) -> None:
        self._credentials, self._kw = credentials, source_kw

    @asynccontextmanager
    async def open(self, tenant_id: str, cluster_id: str,
                   allowed_namespaces: frozenset[str] | None) -> AsyncIterator[EvidenceSource]:
        from ..k8s.source import KubernetesSource

        creds = await self._credentials(tenant_id, cluster_id)
        if creds is None:
            raise UnknownCluster(cluster_id)
        async with KubernetesSource.connect(creds, allowed_namespaces=allowed_namespaces, **self._kw) as src:
            yield src
