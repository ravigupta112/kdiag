"""Optional HTTP service layer: `pip install kdiag[service]`."""
from .app import Deps, create_app
from .auth import Authenticator, Authorizer, GrantAuthorizer, Principal, StaticAuthenticator
from .cache import TTLCache, cache_key
from .registry import ClusterRegistry, InMemoryRegistry, KubernetesRegistry, UnknownCluster
from .settings import ServiceSettings

__all__ = [
    "Authenticator", "Authorizer", "ClusterRegistry", "Deps", "GrantAuthorizer", "InMemoryRegistry",
    "KubernetesRegistry", "Principal", "ServiceSettings", "StaticAuthenticator", "TTLCache",
    "UnknownCluster", "cache_key", "create_app",
]
