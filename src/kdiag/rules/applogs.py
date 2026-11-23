"""Log-signature rules. Low-trust by design: confidence is capped at medium, and these never
outrank a cluster-state finding. Only restricted-charset names are reflected, never log lines."""
from __future__ import annotations

from collections.abc import Iterable

from ..models import Evidence
from .table import TableRule, sub

_M = r"([A-Za-z0-9_.\-]{1,100})"


def _log_lines(ev: Evidence) -> Iterable[tuple[str, str]]:
    for lg in ev.logs:
        ref = f"pod/{lg.pod}/container/{lg.container}" + ("/previous" if lg.previous else "")
        for line in lg.lines:
            yield ref, line


class PythonLogRule(TableRule):
    id, priority, causal_order = "APP-001", 45, 45
    requires = frozenset({"logs"})
    table = (
        sub("module_not_found", r"ModuleNotFoundError: No module named", "medium",
            "The Python app cannot import module {detail} (missing from the image or requirements)",
            "Add the dependency to requirements and rebuild the image",
            rf"No module named '{_M}'"),
        sub("import_error", r"ImportError: cannot import name", "medium",
            "The Python app failed to import the name {detail}",
            "Check dependency versions and the import path",
            rf"cannot import name '{_M}'"),
        sub("syntax_error", r"SyntaxError:", "medium",
            "The Python app has a syntax error", "Fix the code or check the Python version"),
        sub("missing_env", r"KeyError: '[A-Z][A-Z0-9_]{2,60}'", "low",
            "The Python app likely requires an environment variable named {detail}",
            "Provide the variable via the chart (value or Secret reference)",
            r"KeyError: '([A-Z][A-Z0-9_]{2,60})'"),
        sub("address_in_use", r"Address already in use", "medium",
            "The Python app cannot bind its port: it is already in use",
            "Check the port setting and for duplicate listeners"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        return _log_lines(ev)


class NodeLogRule(TableRule):
    id, priority, causal_order = "APP-002", 45, 45
    requires = frozenset({"logs"})
    table = (
        sub("module_not_found", r"Cannot find module", "medium",
            "The Node app cannot find module {detail} (missing from the image)",
            "Install the dependency (and check the build output) in the image",
            r"Cannot find module '([A-Za-z0-9_.@/\-]{1,100})'"),
        sub("port_in_use", r"EADDRINUSE", "medium",
            "The Node app cannot bind its port: it is already in use",
            "Check the PORT setting and for duplicate listeners"),
        sub("heap_oom", r"JavaScript heap out of memory", "medium",
            "The Node process ran out of heap memory",
            "Raise --max-old-space-size and the container memory limit, or reduce memory use"),
        sub("permission", r"EACCES", "medium",
            "The Node app lacks permission (port below 1024 or a file)",
            "Use a higher port or fix file permissions/user"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        return _log_lines(ev)


class NetworkLogRule(TableRule):
    id, priority, causal_order = "APP-003", 30, 50
    requires = frozenset({"logs"})
    table = (
        sub("dns_failure", r"NXDOMAIN|Name or service not known|ENOTFOUND|no such host|Temporary failure in name resolution",
            "low", "The app logs DNS lookup failures (a dependency name may be wrong)",
            "Check the service/host name the app connects to and cluster DNS"),
        sub("connection_refused", r"connection refused|ECONNREFUSED", "low",
            "The app logs refused connections to a dependency",
            "Check that the dependency is running and the port is right"),
    )

    def texts(self, ev: Evidence) -> Iterable[tuple[str, str]]:
        return _log_lines(ev)
