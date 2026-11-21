# kdiag

Deterministic, read-only diagnosis of failed Kubernetes deployments, as a Python library.

Give it evidence (events, pods, Helm output) or a deployment name, and it returns a ranked report
that says **why the deployment failed**, what to do next, and what it could not see.

- **Rule-based.** Same input gives the same report. No LLM runs during diagnosis.
- **Read-only.** No `kubectl`, `helm`, or shell commands. No cluster changes.
- **Honest.** Unknown stays unknown, and partial evidence is always reported.
- **Safe.** Secrets are masked before any rule runs and again in the report.

> **Status: early.** Phase 1 is done: core engine, Helm parser, four rules, bounded collector.
> The Kubernetes adapter and most rules are not built yet. See [Roadmap](#roadmap).

## Install

```bash
pip install -e ".[dev]"
pytest
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
report = asyncio.run(diagnose(inp))
print(render_text(report))
```

```
DIAGNOSED: deployment
CAUSE   Another Helm operation holds the release lock
        confidence: HIGH  rule: HLM-003
NEXT    Wait for the other operation, or inspect the release for a stuck pending-* state
...
```

## Input modes

1. **evidence:** you supply pods, events, and Helm or job output. No cluster access needed.
2. **cluster:** you supply a `Target` (deployment name, optional namespace) and an `EvidenceSource`.
   The library finds the pods and events itself.
3. **hybrid:** both. Supplied evidence is merged with what the source returns.

```python
from kdiag import DiagnosisInput, Target

inp = DiagnosisInput(mode="cluster", target=Target(name="shop-web", namespace="shop-prod"))
report = await diagnose(inp, source)  # source implements EvidenceSource
```

`EvidenceSource` is a small read-only protocol (`find_workloads`, `list_pods`, `list_events`).
A test fake is included in `kdiag.testing`.

## Report statuses

1. `diagnosed`: a cause was found.
2. `partial`: some evidence could not be read; gaps are listed in `partial_errors`.
3. `unknown`: no rule matched. Nothing is guessed.
4. `no_issue_detected`: the evidence looks healthy.
5. `ambiguous_target`: several deployments match; `candidates` lists them.
6. `target_not_found` and `cluster_unreachable`.

Rules that lack the evidence they need appear in `skipped_rules` instead of silently passing.

## Current rules

1. `IMG-001`: image pull failures (not found, auth, network, invalid name, and others).
2. `POD-005`: container killed for exceeding its memory limit.
3. `POD-004`: CrashLoopBackOff (reports the loop, not an invented cause).
4. `SCHED-001`: unschedulable pods (taint, resources, affinity, topology, and others).
5. `HLM-001` to `HLM-009`: Helm lock, conflict, render, YAML, namespace-terminating, timeout.

## Safety guarantees

1. No subprocess or command execution anywhere in the source (enforced by a test).
2. No cluster write calls (enforced by a test).
3. Models have no field that can hold Secret values, tokens, env values, or kubeconfigs.
4. Every source read is time-limited and size-limited; failures become `partial_errors`.
5. Exception text is never copied into reports, because it can carry credentials.

## Add a rule

1. Create a class in `src/kdiag/rules/` with `id`, `priority`, `requires`, and `evaluate(ev)`.
2. Register it in `rules/__init__.py`.
3. Add positive and negative tests in `tests/test_rules.py`.

## Develop

```bash
ruff check src tests
mypy src
pytest
```

## Roadmap

1. Kubernetes adapter (read-only, scoped, rate-limited).
2. Remaining rules: storage, probes, quota and admission, workload controllers, node conditions.
3. Pod and container log collection.
4. Safe, user-initiated AI prompt export.
5. Optional service layer: API, cache, bounded history.

## License

To be decided.
