"""Authentication and authorization contracts. The service enforces them server-side; a hidden UI
control is never treated as permission. Production deployments supply their own implementations."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from starlette.requests import Request


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: frozenset[str] = frozenset()


class Authenticator(Protocol):
    async def authenticate(self, request: Request) -> Principal | None: ...


class Authorizer(Protocol):
    async def visible_namespaces(self, p: Principal, cluster_id: str) -> frozenset[str] | None:
        """None = all namespaces; an empty set = none."""
        ...

    async def can_debug(self, p: Principal) -> bool: ...  # raw-ish data: container logs

    async def can_export(self, p: Principal) -> bool: ...  # hand-off to an external AI

    async def can_view_history(self, p: Principal, cluster_id: str) -> bool: ...

    async def can_upload_kubeconfig(self, p: Principal) -> bool: ...


class StaticAuthenticator:
    """Bearer-token lookup for tests and local development."""

    def __init__(self, tokens: Mapping[str, Principal]) -> None:
        self._tokens = dict(tokens)

    async def authenticate(self, request: Request) -> Principal | None:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        return self._tokens.get(token) if scheme.lower() == "bearer" else None


class GrantAuthorizer:
    """Role + per-tenant cluster/namespace grants. grants[(tenant, cluster)] = namespaces or None."""

    def __init__(self, grants: Mapping[tuple[str, str], frozenset[str] | None], *,
                 debug_roles: frozenset[str] = frozenset({"debugger"}),
                 export_roles: frozenset[str] = frozenset({"exporter", "debugger"}),
                 upload_roles: frozenset[str] = frozenset({"admin"})) -> None:
        self._grants = dict(grants)
        self._debug, self._export, self._upload = debug_roles, export_roles, upload_roles

    async def visible_namespaces(self, p: Principal, cluster_id: str) -> frozenset[str] | None:
        key = (p.tenant_id, cluster_id)
        if key not in self._grants:
            return frozenset()
        return self._grants[key]

    async def can_debug(self, p: Principal) -> bool:
        return bool(p.roles & self._debug)

    async def can_export(self, p: Principal) -> bool:
        return bool(p.roles & self._export)

    async def can_view_history(self, p: Principal, cluster_id: str) -> bool:
        return (p.tenant_id, cluster_id) in self._grants

    async def can_upload_kubeconfig(self, p: Principal) -> bool:
        return bool(p.roles & self._upload)
