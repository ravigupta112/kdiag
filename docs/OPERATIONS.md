# kdiag operations

Starting-point values. Tune after a week of real traffic.

## Metrics

1. Diagnosis: `kdiag_diagnosis_total{mode,status}`, `kdiag_diagnosis_duration_seconds`, `kdiag_unknown_cause_total`, `kdiag_truncated_total`, `kdiag_report_bytes`.
2. Evidence quality: `kdiag_partial_reads_total{resource,reason}`, `kdiag_timeouts_total{resource}`.
3. Rules: `kdiag_rule_matches_total{rule_id}`, `kdiag_rule_exceptions_total{rule_id}`.
4. Masking: `kdiag_masking_events_total` (strings that had something redacted).
5. Kubernetes API: `kdiag_k8s_api_calls_total{resource,verb}`, `kdiag_k8s_api_errors_total{resource,reason}`.
6. HTTP: `kdiag_http_requests_total{route,code}`, `kdiag_rate_limited_total`, `kdiag_backpressure_total`.
7. Cache: `kdiag_cache_total{result}` (hit, miss, coalesced).
8. History: `kdiag_snapshot_total{result}`, `kdiag_snapshot_bytes`, `kdiag_persistence_errors_total`, `kdiag_snapshot_unreadable_total{reason}`, `kdiag_retention_deleted_total`.
9. Sharing: `kdiag_prompt_exports_total{result}`, `kdiag_kubeconfig_rejected_total{code}`.

Labels are enums, rule ids and resource kinds. Never evidence content.

## Dashboard panels

1. Diagnoses per minute by status, and p50/p95 `kdiag_diagnosis_duration_seconds`.
2. Unknown rate (`kdiag_unknown_cause_total` / `kdiag_diagnosis_total`) and top rules by `kdiag_rule_matches_total`.
3. Partial reads by resource and reason; timeouts by resource.
4. Kubernetes API errors by reason; rate-limit and backpressure counters.
5. Cache hit ratio; snapshot results and persistence errors.
6. Masking events and blocked exports (should be near zero).

## Runbook

### Unknown rate high
1. Open recent unknown reports. Look for one failure shape repeating.
2. Add a sub-cause row or rule with a fixture (see README, "Add a rule"). Do not loosen an existing pattern to catch it.
3. If the cause is missing evidence, check partial reads first.

### Rule exceptions
1. The report still works; the rule is skipped and named in `rule_errors`.
2. Find the rule id in `kdiag_rule_exceptions_total`, reproduce with its fixture, fix, release.
3. Until then the rule can be removed from the registry without affecting others.

### Partial reads high
1. Group by `resource` and `reason`. `forbidden` means RBAC: re-apply `deploy/rbac.yaml` for the namespace.
2. `timeout` or `unreachable`: see timeouts. `rate_limited`: lower concurrency or the per-principal rate.
3. Reads of `nodes` and `namespace` are optional; they appear in reports but do not make a diagnosis partial.

### Timeouts high
1. Check API server health and network path to the cluster.
2. If only large namespaces time out, lower `KDIAG_MAX_EVENTS` and `KDIAG_MAX_PODS`, or raise `KDIAG_REQUEST_TIMEOUT_S` cautiously.
3. The overall deadline (`KDIAG_OVERALL_TIMEOUT_S`) always bounds a request.

### Backpressure
1. 503 with `Retry-After` is the service protecting itself. Check `KDIAG_MAX_CONCURRENT` against API server capacity.
2. Raise it only if cluster API latency is healthy. Prefer more replicas.

### Persistence errors
1. History is best-effort: diagnoses keep working, responses carry `save_error`.
2. Check disk space and the database file. Run `purge` if retention has not run.
3. Never edit report bodies by hand; corrupt rows are shown as unreadable and are replaced by the next diagnosis for that job.

### Slow diagnoses
1. Check partial reads and API latency first; most slowness is the cluster.
2. Check report size and truncation; very large workloads hit the fetch ceilings by design.

### Exports blocked
1. A block means sensitive-looking text survived masking. Treat it as a masking bug.
2. Find the pattern in the blocked report, add it to the masker with a test, and review recent exports for the same shape.

## Safe degradation

1. Missing permission or API errors: the report is `partial`, lists the gaps, and never says "healthy".
2. Cluster unreachable: 502 or 504 with retry guidance; supplied evidence is still analysed.
3. History store down: diagnoses continue without saving.
4. Overload: requests queue briefly, then get 503; nothing runs unbounded.
5. Masking failure: the field is dropped, never shown raw.

## Settings (environment)

`KDIAG_ENABLED`, `KDIAG_SHADOW_MODE`, `KDIAG_ALLOW_KUBECONFIG_UPLOAD`, `KDIAG_KUBECONFIG_ALLOWED_HOSTS`, `KDIAG_KUBECONFIG_ALLOW_PRIVATE`, `KDIAG_MAX_PODS`, `KDIAG_MAX_EVENTS`, `KDIAG_REQUEST_TIMEOUT_S`, `KDIAG_OVERALL_TIMEOUT_S`, `KDIAG_CACHE_TTL_S`, `KDIAG_CACHE_MAX_ENTRIES`, `KDIAG_MAX_CONCURRENT`, `KDIAG_QUEUE_WAIT_S`, `KDIAG_RATE_PER_S`, `KDIAG_RATE_BURST`.

Limits are set here, never from request bodies. Kubeconfig upload stays off unless security approves it.

## Rollout

1. Deploy with `KDIAG_ENABLED=true` and `KDIAG_SHADOW_MODE=true`. Requests run and metrics fill, but callers get 202 and no report.
2. Watch unknown rate, partial reads, timeouts and masking events for a week. Review a sample of reports with operators.
3. Turn shadow off for a small operator group, then everyone.
4. Enable history and exports last, each behind its own authorization role.

## Rollback

1. Set `KDIAG_ENABLED=false`. Every route answers 404 immediately; no restart of dependencies is needed.
2. Stored history is untouched and readable again when re-enabled.
3. A bad rule release: roll back the package. Reports store their `schema_version`, so older and newer reports stay readable.

## Housekeeping

1. Run the store `purge` on a schedule (daily). It applies age, per-target and per-tenant limits.
2. Apply `deploy/rbac.yaml` per namespace; rotate the ServiceAccount token on your normal credential schedule.
3. Alert rules live in `deploy/alerts.yaml`; a test keeps them in sync with the metrics the code emits.
