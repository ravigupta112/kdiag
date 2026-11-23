"""Wire the optional HTTP service. Run: pip install "kdiag[k8s,service]" uvicorn && uvicorn examples.serve:app

Replace the authenticator, authorizer and credential lookup with your platform's own.
"""
from kdiag.observability import PrometheusMetrics
from kdiag.service import (
    Deps,
    GrantAuthorizer,
    KubernetesRegistry,
    Principal,
    ServiceSettings,
    StaticAuthenticator,
    create_app,
)
from kdiag.store import SqliteStore


async def credentials(tenant_id: str, cluster_id: str):
    """Return ClusterCredentials(server, token, ca_pem) from your secret store, or None if unknown.
    Use a read-only ServiceAccount token (see deploy/rbac.yaml). Never log or cache it."""
    return


app = create_app(Deps(
    settings=ServiceSettings.from_env(),
    authenticator=StaticAuthenticator({"dev-token": Principal("me", "tenant-1", frozenset({"debugger"}))}),
    authorizer=GrantAuthorizer({("tenant-1", "prod"): None}),
    registry=KubernetesRegistry(credentials),
    store=SqliteStore("kdiag-history.db"),
    metrics=PrometheusMetrics(),
))
