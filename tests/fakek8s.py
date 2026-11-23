"""In-memory fake of the kubernetes_asyncio API objects. Records every operation name."""
from __future__ import annotations

from types import SimpleNamespace as NS
from typing import Any

from kubernetes_asyncio import client

from kdiag.k8s.source import K8sApis


def meta(name: str, ns: str = "shop", uid: str | None = None, labels: dict[str, str] | None = None,
         owners: list[tuple[str, str]] | None = None, generation: int = 1, created: str = "2026-11-21T10:00:00") -> Any:
    refs = [client.V1OwnerReference(api_version="v1", kind=k, name="o", uid=u) for k, u in owners or []]
    return client.V1ObjectMeta(name=name, namespace=ns, uid=uid or f"uid-{name}", labels=labels,
                               owner_references=refs or None, generation=generation)


def v1pod(name: str, owner_uid: str | None = "rs-1", phase: str = "Running", labels: dict[str, str] | None = None,
          containers: list[Any] | None = None, node: str | None = "node-1", claims: tuple[str, ...] = (),
          env_secret: str | None = None, mem: str | None = None, reason: str | None = None,
          ns: str = "shop") -> Any:
    envs = [client.V1EnvVar(name="DB_PASSWORD", value=env_secret)] if env_secret else None
    res = client.V1ResourceRequirements(limits={"memory": mem}) if mem else None
    spec = client.V1PodSpec(
        containers=[client.V1Container(name="web", env=envs, resources=res)], node_name=node,
        volumes=[client.V1Volume(name=f"v{i}", persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=c))
                 for i, c in enumerate(claims)] or None)
    status = client.V1PodStatus(phase=phase, reason=reason, container_statuses=containers)
    return client.V1Pod(metadata=meta(name, ns, labels=labels or {"app": "web"},
                                      owners=[("ReplicaSet", owner_uid)] if owner_uid else None),
                        spec=spec, status=status)


def cstatus(ready: bool = True, restarts: int = 0, waiting: tuple[str, str] | None = None,
            last_term: tuple[int, str, str] | None = None) -> Any:
    state = client.V1ContainerState(
        waiting=client.V1ContainerStateWaiting(reason=waiting[0], message=waiting[1]) if waiting else None,
        running=None if waiting else client.V1ContainerStateRunning())
    last = client.V1ContainerState(terminated=client.V1ContainerStateTerminated(
        exit_code=last_term[0], reason=last_term[1], message=last_term[2])) if last_term else None
    return client.V1ContainerStatus(name="web", image="img", image_id="", ready=ready,
                                    restart_count=restarts, state=state, last_state=last)


def v1event(kind: str, name: str, reason: str, message: str, type_: str = "Warning", ns: str = "shop",
            last: str | None = None) -> Any:
    from datetime import datetime
    return client.CoreV1Event(
        metadata=meta(f"{name}.{reason}", ns), involved_object=client.V1ObjectReference(kind=kind, name=name),
        reason=reason, message=message, type=type_,
        last_timestamp=datetime.fromisoformat(last) if last else None)


def deployment(name: str = "shop-web", ns: str = "shop", uid: str = "dep-1", replicas: int = 2) -> Any:
    return NS(metadata=meta(name, ns, uid=uid, generation=3),
              spec=NS(selector=NS(match_labels={"app": "web"}), replicas=replicas),
              status=NS(observed_generation=3, updated_replicas=replicas, ready_replicas=replicas,
                        available_replicas=replicas, conditions=[]))


def replicaset(name: str, owner_uid: str = "dep-1", ns: str = "shop") -> Any:
    return NS(metadata=meta(name, ns, uid=f"rs-{name}", owners=[("Deployment", owner_uid)]))


class FakeApi:
    """Stands in for CoreV1Api/AppsV1Api/BatchV1Api/DiscoveryV1Api at once."""

    def __init__(self, **objs: Any) -> None:
        self.calls: list[str] = []
        self.call_kwargs: list[tuple[str, dict[str, Any]]] = []
        self.errors: dict[str, Any] = {}
        self.deployments: list[Any] = objs.get("deployments", [])
        self.statefulsets: list[Any] = objs.get("statefulsets", [])
        self.replicasets: list[Any] = objs.get("replicasets", [])
        self.pods: list[Any] = objs.get("pods", [])
        self.events: list[Any] = objs.get("events", [])
        self.nodes: list[Any] = objs.get("nodes", [])
        self.pvcs: list[Any] = objs.get("pvcs", [])
        self.services: list[Any] = objs.get("services", [])
        self.slices: list[Any] = objs.get("slices", [])
        self.jobs: list[Any] = objs.get("jobs", [])
        self.cronjobs: list[Any] = objs.get("cronjobs", [])
        self.namespaces: list[str] = objs.get("namespaces", ["shop"])
        self.logs: dict[tuple[str, bool], str] = objs.get("logs", {})

    def apis(self) -> K8sApis:
        return K8sApis(self, self, self, self)

    def _rec(self, op: str, **kw: Any) -> None:
        self.calls.append(op)
        self.call_kwargs.append((op, kw))
        err = self.errors.get(op)
        if err:
            raise err.pop(0) if isinstance(err, list) else err

    @staticmethod
    def _page(items: list[Any], limit: int | None, token: str | None) -> Any:
        start = int(token or 0)
        end = len(items) if limit is None else min(len(items), start + limit)
        nxt = str(end) if end < len(items) else None
        return NS(items=items[start:end], metadata=NS(_continue=nxt))

    @staticmethod
    def _match(obj: Any, selector: str | None) -> bool:
        if not selector:
            return True
        labels = obj.metadata.labels or {}
        return all(labels.get(k) == v for k, _, v in (p.partition("=") for p in selector.split(",")))

    @staticmethod
    def _find(items: list[Any], name: str, ns: str | None = None) -> Any:
        for o in items:
            if o.metadata.name == name and (ns is None or o.metadata.namespace == ns):
                return o
        raise client.ApiException(status=404, reason="Not Found")

    async def list_namespace(self, limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespace")
        return self._page([NS(metadata=NS(name=n)) for n in self.namespaces], limit, _continue)

    async def read_namespace(self, name: str, **_: Any) -> Any:
        self._rec("read_namespace")
        return NS(status=NS(phase="Terminating" if name == "gone" else "Active"))

    async def read_namespaced_deployment(self, name: str, namespace: str) -> Any:
        self._rec("read_namespaced_deployment")
        return self._find(self.deployments, name, namespace)

    async def read_namespaced_stateful_set(self, name: str, namespace: str) -> Any:
        self._rec("read_namespaced_stateful_set")
        return self._find(self.statefulsets, name, namespace)

    async def read_namespaced_job(self, name: str, namespace: str) -> Any:
        self._rec("read_namespaced_job")
        return self._find(self.jobs, name, namespace)

    async def read_namespaced_cron_job(self, name: str, namespace: str) -> Any:
        self._rec("read_namespaced_cron_job")
        return self._find(self.cronjobs, name, namespace)

    async def list_namespaced_replica_set(self, namespace: str, label_selector: str | None = None,
                                          limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespaced_replica_set", label_selector=label_selector)
        return self._page([r for r in self.replicasets if r.metadata.namespace == namespace], limit, _continue)

    async def list_namespaced_pod(self, namespace: str, label_selector: str | None = None,
                                  limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespaced_pod", label_selector=label_selector, limit=limit, cont=_continue)
        items = [p for p in self.pods if p.metadata.namespace == namespace and self._match(p, label_selector)]
        return self._page(items, limit, _continue)

    async def list_namespaced_job(self, namespace: str, limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespaced_job")
        return self._page([j for j in self.jobs if j.metadata.namespace == namespace], limit, _continue)

    async def list_namespaced_event(self, namespace: str, limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespaced_event")
        return self._page([e for e in self.events if e.metadata.namespace == namespace], limit, _continue)

    async def read_node(self, name: str, **_: Any) -> Any:
        self._rec("read_node")
        return self._find(self.nodes, name)

    async def read_namespaced_persistent_volume_claim(self, name: str, namespace: str) -> Any:
        self._rec("read_namespaced_persistent_volume_claim")
        return self._find(self.pvcs, name, namespace)

    async def list_namespaced_service(self, namespace: str, limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespaced_service")
        return self._page([s for s in self.services if s.metadata.namespace == namespace], limit, _continue)

    async def list_namespaced_endpoint_slice(self, namespace: str, limit: int | None = None, _continue: str | None = None) -> Any:
        self._rec("list_namespaced_endpoint_slice")
        return self._page([s for s in self.slices if s.metadata.namespace == namespace], limit, _continue)

    async def read_namespaced_pod_log(self, name: str, namespace: str, container: str = "", previous: bool = False,
                                      tail_lines: int | None = None, limit_bytes: int | None = None) -> str:
        self._rec("read_namespaced_pod_log", previous=previous, tail=tail_lines)
        if (name, previous) not in self.logs:
            raise client.ApiException(status=400, reason="Bad Request")
        return self.logs[(name, previous)]
