# kdiag

Deterministic, read-only diagnosis of failed Kubernetes deployments, as a Python library with an
optional HTTP service.

Give it evidence (events, pods, Helm output) or a deployment name, and it returns a ranked report:
**why the deployment failed**, what to do next, and what it could not see.

- **Rule-based.** Same input gives the same report. No LLM runs during diagnosis.
- **Read-only.** No `kubectl`, `helm`, or shell commands. No cluster changes. No Secret reads.
- **Honest.** Unknown stays unknown. Partial or truncated evidence is always reported, and never called healthy.
- **Safe.** Secrets are masked before any rule runs, again in the report, and a final scan blocks exports and history writes.

> **Status: 0.2.** Tested against in-memory fakes and a recording fake of the Kubernetes API.
> **Not yet tested against a live cluster.** Do that in a non-production cluster before relying on it.

## Install

```bash
pip install -e ".[dev]"      # everything, for development
pytest                       # 468 tests

pip install kdiag            # core only (depends on pydantic alone)
pip install "kdiag[k8s]"     # + Kubernetes adapter
pip install "kdiag[service]" # + HTTP service
pip install "kdiag[metrics]" # + Prometheus metrics
```

Requires Python 3.11+.

## Quick start

```python
import asyncio
from kdiag import DiagnosisInput, diagnose, render_text

inp = DiagnosisInput(
    mode="evidence",
    helm_output="Error: UPGRADE FAILED: another operation (install/upgrade/rollback) is in progress",
)
print(render_text(asyncio.run(diagnose(inp))))
```

## Three ways in

1. **evidence:** you supply pods, events, nodes, logs, Helm or job output. No cluster access.
2. **cluster:** you supply a `Target` (deployment name, optional namespace). The library finds pods,
   events, services, volumes, nodes and optionally logs itself.
3. **hybrid:** both. A failed job log narrows the cause; the cluster confirms it.

```python
from kdiag import DiagnosisInput, Target
from kdiag.k8s import ClusterCredentials
from kdiag.k8s.source import KubernetesSource

creds = ClusterCredentials(server="https://k8s.example.com", token=TOKEN, ca_pem=CA_PEM)
async with KubernetesSource.connect(creds, allowed_namespaces=frozenset({"shop"})) as source:
    report = await diagnose(
        DiagnosisInput(mode="cluster", target=Target(name="shop-web", namespace="shop")), source)
```

## Report statuses

1. `diagnosed`: a cause was found.
2. `partial`: some required evidence could not be read; gaps are listed.
3. `unknown`: no rule matched, or evidence was truncated. Nothing is guessed.
4. `no_issue_detected`: pods are healthy, the rollout is complete, and everything was inspected.
5. `ambiguous_target`, `target_not_found`, `cluster_unreachable`.

## What it can diagnose

21 rules cover scheduling, images, config references, container start, crash loops, OOM, eviction,
probes, admission (quota, policy, webhooks, RBAC), volumes, services, CNI, nodes, namespaces, jobs,
rollouts, Helm (14 failure types), and low-trust log signatures (Python, Node, network).

The team's 173-item error list is mapped in `coverage_map.yaml`, enforced by a CI test with
executable samples:

1. **131 items** have a rule (66 have a runnable sample proving it fires).
2. **23 items** are an honest gap: they need Ingress, NetworkPolicy, HPA, cert-manager, DNS or kubelet
   evidence that is not read yet.
3. **The other 19** are normal states, generic symptoms, source errors, or out of scope.

## HTTP service (optional)

`kdiag.service` provides `POST /v1/diagnose`, history (`/v1/reports`), and prompt export. It enforces,
server-side: authentication, per-tenant isolation, cluster and namespace grants, debug authorization for
logs, per-user rate limits, a concurrency gate (503 under load), a tenant-keyed TTL cache with
single-flight, request size limits, and a feature flag with shadow mode.
Clients can never set limits, tenant, or authorization. See `examples/serve.py`.

- Operations, metrics, alerts, runbooks, rollout and rollback: `docs/OPERATIONS.md`, `deploy/alerts.yaml`.
- Read-only RBAC (no Secrets, no write verbs): `deploy/rbac.yaml`.

## Safety guarantees (each is enforced by a test)

1. No command execution anywhere in the source tree.
2. The Kubernetes adapter uses only `read_`/`list_` operations, never Secret, exec or attach APIs.
3. No model field can hold Secret values, tokens, env values or kubeconfigs.
4. Uploaded kubeconfigs: token-only, verified TLS, no exec plugins, no file paths, no proxies, SSRF
   checks, held in memory only. Upload is off by default.
5. Prompt export needs explicit consent, makes no network call, and refuses if anything sensitive survives.
6. History is tenant-scoped, size-capped, bounded by retention, and refuses to store sensitive-looking text.
7. A planted-secret sweep over responses, history, exports, audit, metrics and logs finds nothing.
8. The library imports no AI client, and its core depends on `pydantic` only.

## Known limitations

1. **No live-cluster test yet.** Message formats differ across Kubernetes versions and CNI/CSI plugins.
2. Masking is pattern-based. Bare `AUTH=` keys are not masked (it would mangle `unauthorized`); a secret
   with no recognisable key or shape can still pass. Keep logs behind debug authorization.
3. Kubeconfig hostnames are resolved once at upload; DNS rebinding afterwards is not blocked.
4. The cache, rate limiter and single-flight are per process; with several replicas each keeps its own.
5. History uses SQLite (single node). The SQL is portable; a Postgres store is future work.
6. Ad-hoc history (evidence mode, uploads) is readable by anyone in the creating tenant.
7. If a workload has more pods than the fetch ceiling, failing pods past it are not seen; the report says
   it was truncated and never claims health.
8. Rollout status covers Deployment/StatefulSet. Helm retry recovery depends on Helm's success text.
9. A pod `Unschedulable` during a cluster-autoscaler scale-up is reported as a cause.

## Layout

```
src/kdiag/        models, mask, helm parser, normalize, collect, engine, report, export, store
src/kdiag/rules/  table-driven rules by family
src/kdiag/k8s/    adapter, kubeconfig vetting, rate limiter, SDK converters
src/kdiag/service/ optional HTTP layer
deploy/           rbac.yaml, alerts.yaml        docs/OPERATIONS.md
coverage_map.yaml tests/ examples/
```

## Add a rule

1. For a new sub-cause, add one `sub(...)` row to the matching table in `src/kdiag/rules/`.
2. For a new family, subclass `TableRule` (or implement `id`, `priority`, `requires`, `evaluate`) and
   register it in `rules/__init__.py`.
3. Add positive and negative tests, and update `coverage_map.yaml` if it maps a listed item.

## Develop

```bash
ruff check src tests && mypy src && pytest
```

## License

MIT License. See [LICENSE](LICENSE).
