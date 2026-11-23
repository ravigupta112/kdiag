"""Safe kubeconfig intake.

A kubeconfig is a program-shaped file: it can name commands to run (exec plugins), files to read
(token/cert paths), proxies, and arbitrary server addresses. This parser accepts only a strict
subset (server + CA data + bearer token over verified TLS) and rejects everything else, naming the
rejected *field* but never echoing a value. Credentials live in memory only.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import yaml

Resolver = Callable[[str], Awaitable[Sequence[str]]]

_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,8192}$")
_REJECT_USER_KEYS = {
    "exec": ("exec_plugin", "exec credential plugins run external programs and are not supported"),
    "auth-provider": ("auth_provider", "auth-provider plugins are not supported"),
    "tokenFile": ("file_reference", "file references are not read; send the token itself"),
    "client-certificate": ("client_cert_unsupported", "client certificates are not supported; use a token"),
    "client-certificate-data": ("client_cert_unsupported", "client certificates are not supported; use a token"),
    "client-key": ("client_cert_unsupported", "client certificates are not supported; use a token"),
    "client-key-data": ("client_cert_unsupported", "client certificates are not supported; use a token"),
    "username": ("basic_auth", "basic auth is not supported"),
    "password": ("basic_auth", "basic auth is not supported"),
    "as": ("impersonation", "impersonation is not supported"),
    "as-groups": ("impersonation", "impersonation is not supported"),
    "as-uid": ("impersonation", "impersonation is not supported"),
    "as-user-extra": ("impersonation", "impersonation is not supported"),
}
_REJECT_CLUSTER_KEYS = {
    "certificate-authority": ("file_reference", "file references are not read; use certificate-authority-data"),
    "proxy-url": ("proxy", "proxies are not supported"),
}


class KubeconfigRejected(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, repr=False)
class ClusterCredentials:
    server: str
    token: str = field(repr=False)
    ca_pem: str | None = None

    def __repr__(self) -> str:
        return f"ClusterCredentials(server={self.server!r}, token=<redacted>)"


def _host_matches(host: str, patterns: Sequence[str]) -> bool:
    host = host.lower()
    for p in patterns:
        p = p.lower()
        if p == host or (p.startswith("*.") and host.endswith(p[1:]) and host != p[2:]):
            return True
    return False


async def _default_resolver(host: str) -> Sequence[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    return sorted({str(i[4][0]) for i in infos})


def _pick(items: Any, name: str, key: str, what: str) -> dict[str, Any]:
    for it in items or []:
        if isinstance(it, dict) and it.get("name") == name and isinstance(it.get(key), dict):
            return it[key]  # type: ignore[no-any-return]
    raise KubeconfigRejected("invalid_kubeconfig", f"{what} referenced by the context was not found")


async def parse_kubeconfig(
    text: str,
    *,
    context: str | None = None,
    allowed_hosts: Sequence[str] = (),
    allow_private: bool = False,
    resolver: Resolver | None = None,
    max_bytes: int = 262_144,
) -> ClusterCredentials:
    """Parse and vet a kubeconfig. Raises KubeconfigRejected; never returns partial credentials.

    Address policy: if `allowed_hosts` is set the server host must match it (private addresses are
    then fine, since the operator chose them). Otherwise the host must resolve only to public
    addresses unless `allow_private` is set. Note: resolution happens once here; pin or re-check at
    connect time if DNS rebinding is in your threat model.
    """
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        raise KubeconfigRejected("too_large", "kubeconfig is too large")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        raise KubeconfigRejected("invalid_yaml", "kubeconfig is not valid YAML") from None
    if not isinstance(doc, dict):
        raise KubeconfigRejected("invalid_kubeconfig", "kubeconfig must be a mapping")

    ctx_name = context or doc.get("current-context")
    if not isinstance(ctx_name, str):
        contexts = doc.get("contexts") or []
        if len(contexts) == 1 and isinstance(contexts[0], dict):
            ctx_name = contexts[0].get("name")
    if not isinstance(ctx_name, str):
        raise KubeconfigRejected("no_context", "no current-context; choose a context")
    ctx = _pick(doc.get("contexts"), ctx_name, "context", "context")
    cluster = _pick(doc.get("clusters"), str(ctx.get("cluster")), "cluster", "cluster")
    user = _pick(doc.get("users"), str(ctx.get("user")), "user", "user")

    for key, (code, msg) in _REJECT_USER_KEYS.items():
        if key in user:
            raise KubeconfigRejected(code, f"{msg} (field: {key})")
    for key, (code, msg) in _REJECT_CLUSTER_KEYS.items():
        if key in cluster:
            raise KubeconfigRejected(code, f"{msg} (field: {key})")
    if cluster.get("insecure-skip-tls-verify"):
        raise KubeconfigRejected("insecure_tls", "TLS verification cannot be disabled")
    for key in cluster:
        if key not in {"server", "certificate-authority-data", "insecure-skip-tls-verify", "extensions"}:
            raise KubeconfigRejected("unsupported_field", f"unsupported cluster field: {str(key)[:40]}")
    for key in user:
        if key not in {"token"}:
            raise KubeconfigRejected("unsupported_field", f"unsupported user field: {str(key)[:40]}")

    token = user.get("token")
    if not isinstance(token, str) or not _TOKEN_RE.match(token):
        raise KubeconfigRejected("no_token", "a bearer token (without spaces or newlines) is required")

    server = cluster.get("server")
    parts = urlsplit(server) if isinstance(server, str) else None
    if parts is None or parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise KubeconfigRejected("bad_server", "server must be an https URL without credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise KubeconfigRejected("bad_server", "server must not include a path or query")
    host = parts.hostname
    try:
        parts.port  # noqa: B018 - validates the port
    except ValueError:
        raise KubeconfigRejected("bad_server", "server port is invalid") from None

    if allowed_hosts:
        if not _host_matches(host, allowed_hosts):
            raise KubeconfigRejected("host_not_allowed", "server host is not on the allowlist")
    elif not allow_private:
        try:
            addrs: Sequence[str] = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                addrs = await (resolver or _default_resolver)(host)
            except OSError:
                raise KubeconfigRejected("bad_server", "server host could not be resolved") from None
        if not addrs:
            raise KubeconfigRejected("bad_server", "server host could not be resolved")
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if not ip.is_global:
                raise KubeconfigRejected(
                    "private_address", "server resolves to a non-public address; use the allowlist")

    ca_pem: str | None = None
    if (ca := cluster.get("certificate-authority-data")) is not None:
        try:
            ca_pem = base64.b64decode(str(ca), validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            raise KubeconfigRejected("bad_ca", "certificate-authority-data is not valid base64 PEM") from None
        if "-----BEGIN CERTIFICATE-----" not in ca_pem or len(ca_pem) > 65_536 or "PRIVATE KEY" in ca_pem:
            raise KubeconfigRejected("bad_ca", "certificate-authority-data must contain CA certificates only")

    return ClusterCredentials(server=f"https://{parts.netloc}", token=token, ca_pem=ca_pem)
