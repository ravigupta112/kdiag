from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest

from conftest import NOW, ctr, pod, pull_pod, run, unschedulable
from kdiag import DiagnosisInput, Target, diagnose
from kdiag.models import DiagnosisReport, Finding
from kdiag.store import (
    LATEST,
    MIGRATIONS,
    PersistRefused,
    RetentionPolicy,
    SqliteStore,
    migrate,
)

PULL = 'Failed to pull image "registry.example.com/shop/web:2.4.1": manifest unknown'
TGT = Target(name="shop-web", namespace="shop")


def rep(**kw) -> DiagnosisReport:
    return run(diagnose(DiagnosisInput(mode="evidence", target=None, **kw), now=NOW)).model_copy(update={"target": TGT})


diagnosed = rep(pods=(pull_pod(PULL),))
unknown = rep(pods=(pod(phase="Pending"),))
partial = diagnosed.model_copy(update={"status": "partial"})


def test_migrations_apply_in_order_idempotently_and_upgrade_old_databases() -> None:
    conn = sqlite3.connect(":memory:")
    assert migrate(conn, target=1) == 1  # an "old" v1 database with data
    conn.execute("INSERT INTO reports VALUES ('a','t','c','ns','Deployment','x','j',1,'diagnosed','R',"
                 "'2026-01-01','2026-01-01',10,'h','{}')")
    conn.commit()
    assert migrate(conn) == LATEST and migrate(conn) == LATEST
    conn.row_factory = sqlite3.Row
    assert conn.execute("SELECT history FROM reports").fetchone()["history"] == "[]"  # backfilled default
    assert [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY 1")] == [v for v, _ in MIGRATIONS]


def test_failed_migration_rolls_back_cleanly() -> None:
    conn = sqlite3.connect(":memory:")
    migrate(conn, target=1)
    import kdiag.store as st
    broken = (*st.MIGRATIONS, (3, ("CREATE TABLE ok_table (x)", "THIS IS NOT SQL")))
    old = st.MIGRATIONS
    try:
        st.MIGRATIONS = broken
        with pytest.raises(sqlite3.Error):
            migrate(conn)
    finally:
        st.MIGRATIONS = old
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='ok_table'").fetchone() is None
    assert conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 2


def test_save_get_roundtrip_and_tenant_isolation() -> None:
    s = SqliteStore()
    res = run(s.save("tenantA", "prod", diagnosed))
    assert res.action == "created"
    got = run(s.get("tenantA", res.id))
    assert got and got.report and got.report.primary and got.report.primary.rule_id == "IMG-001"
    assert got.summary.cluster_id == "prod" and got.summary.target_name == "shop-web"
    assert run(s.get("tenantB", res.id)) is None  # other tenant cannot read it
    assert run(s.list_for_target("tenantB", "prod", "shop", "shop-web")) == []
    assert len(run(s.list_for_target("tenantA", "prod", "shop", "shop-web"))) == 1
    assert run(s.get("tenantA", "does-not-exist")) is None


def test_merge_by_job_better_replaces_worse_is_kept_and_identical_is_deduped() -> None:
    s = SqliteStore()
    first = run(s.save("t", "c", unknown, job_id="job-1", now=NOW))
    better = run(s.save("t", "c", diagnosed, job_id="job-1", now=NOW + timedelta(minutes=1)))
    assert (first.action, better.action) == ("created", "replaced") and first.id == better.id
    worse = run(s.save("t", "c", unknown, job_id="job-1", now=NOW + timedelta(minutes=2)))
    assert worse.action == "kept"
    same = run(s.save("t", "c", diagnosed, job_id="job-1", now=NOW + timedelta(minutes=3)))
    assert same.action == "deduped"
    got = run(s.get("t", first.id))
    assert got and got.report and got.report.status == "diagnosed"
    assert [h["outcome"] for h in got.history] == ["not_better", "superseded"]
    assert run(s.count("t")) == 1  # one row per job
    assert run(s.save("t", "c", diagnosed, job_id="job-2")).id != first.id
    assert run(s.save("t", "other-cluster", diagnosed, job_id="job-1")).id != first.id  # job ids are per cluster
    assert run(s.save("t2", "c", diagnosed, job_id="job-1")).id != first.id  # and per tenant


def test_partial_with_primary_beats_unknown_but_not_diagnosed() -> None:
    s = SqliteStore()
    run(s.save("t", "c", diagnosed, job_id="j"))
    assert run(s.save("t", "c", partial, job_id="j")).action == "kept"
    s2 = SqliteStore()
    run(s2.save("t", "c", unknown, job_id="j"))
    assert run(s2.save("t", "c", partial, job_id="j")).action == "replaced"


def test_history_is_bounded() -> None:
    s = SqliteStore()
    rid = run(s.save("t", "c", diagnosed, job_id="j")).id
    for i in range(12):
        run(s.save("t", "c", unknown.model_copy(update={"stale_events_suppressed": i}), job_id="j"))
    got = run(s.get("t", rid))
    assert got and len(got.history) == 5


def test_oversize_report_is_shrunk_under_the_cap_and_flagged() -> None:
    pods = tuple(pull_pod(PULL + f" v{i}", name=f"p{i}") for i in range(6)) + (
        unschedulable("0/3 nodes are available: 3 Insufficient cpu."),
        pod("c", containers=[ctr(waiting_reason="CrashLoopBackOff", last_exit_code=2)]))
    big = rep(pods=pods)
    full = len(big.model_dump_json().encode())
    s = SqliteStore(max_report_bytes=full - 200)
    res = run(s.save("t", "c", big))
    assert res.shrunk and res.size_bytes <= full - 200
    got = run(s.get("t", res.id))
    assert got and got.report and got.report.truncated and got.report.primary


def test_unshrinkable_report_is_refused() -> None:
    s = SqliteStore(max_report_bytes=1024)
    f = Finding(rule_id="X", sub_cause="s", confidence="high", summary="a" * 300, next_action="b" * 300,
                evidence_refs=tuple(f"pod/{'p' * 200}-{i}" for i in range(3)), details={"k": "v" * 900})
    huge = DiagnosisReport(status="diagnosed", mode="evidence", primary=f, collected_at=NOW,
                           partial_errors=(), candidates=tuple("c" * 250 for _ in range(5)),
                           notes=(), target=Target(name="x"))
    with pytest.raises(PersistRefused):
        run(s.save("t", "c", huge))
    assert run(s.count()) == 0


def test_store_refuses_to_persist_sensitive_looking_reports() -> None:
    leaky = DiagnosisReport(
        status="diagnosed", mode="evidence", collected_at=NOW,
        primary=Finding(rule_id="X", sub_cause="s", confidence="high",
                        summary="oops password=hunter2-canary", next_action="n"))
    s = SqliteStore()
    with pytest.raises(PersistRefused):
        run(s.save("t", "c", leaky))
    assert run(s.count()) == 0


def test_corrupt_newer_and_invalid_bodies_are_reported_not_raised() -> None:
    s = SqliteStore()
    ids = {k: run(s.save("t", "c", diagnosed, job_id=k)).id for k in ("corrupt", "newer", "invalid", "notdict")}
    doc = json.loads(diagnosed.model_dump_json())
    bodies = {"corrupt": "{not json", "newer": json.dumps(doc | {"schema_version": 99}),
              "invalid": json.dumps(doc | {"status": "bogus-status"}), "notdict": "[1,2]"}
    for k, body in bodies.items():
        s._conn.execute("UPDATE reports SET body=? WHERE id=?", (body, ids[k]))
    got = {k: run(s.get("t", i)) for k, i in ids.items()}
    assert [got[k].unreadable for k in ("corrupt", "newer", "invalid", "notdict")] == [
        "corrupt", "newer_schema", "invalid", "corrupt"]
    assert all(g.report is None and g.summary.id for g in got.values())


def test_corrupt_old_body_is_replaced_by_a_new_diagnosis() -> None:
    s = SqliteStore()
    rid = run(s.save("t", "c", diagnosed, job_id="j")).id
    s._conn.execute("UPDATE reports SET body='{bad' WHERE id=?", (rid,))
    assert run(s.save("t", "c", unknown, job_id="j")).action == "replaced"
    got = run(s.get("t", rid))
    assert got and got.report and got.report.status == "unknown"


def test_retention_by_age_per_target_and_per_tenant() -> None:
    s = SqliteStore(retention=RetentionPolicy(max_age_days=30, max_per_target=3, max_rows_per_tenant=5))
    for i in range(6):  # same target: only the newest 3 survive
        run(s.save("t", "c", diagnosed.model_copy(update={"stale_events_suppressed": i}), now=NOW - timedelta(days=i)))
    run(s.save("t", "c", diagnosed, now=NOW - timedelta(days=90)))  # too old
    assert run(s.purge(now=NOW)) == 4 and run(s.count("t")) == 3
    other = diagnosed.model_copy(update={"target": Target(name="other", namespace="shop")})
    for i in range(4):
        run(s.save("t", "c", other.model_copy(update={"stale_events_suppressed": i}), now=NOW - timedelta(hours=i)))
    run(s.purge(now=NOW))
    assert run(s.count("t")) <= 5
    run(s.save("u", "c", diagnosed, now=NOW))
    assert run(s.count("u")) == 1  # another tenant is unaffected by t's caps


def test_rerunning_the_same_diagnosis_at_another_time_is_a_duplicate_not_a_new_version() -> None:
    s = SqliteStore()
    later = diagnosed.model_copy(update={"collected_at": NOW + timedelta(hours=1)})
    first = run(s.save("t", "c", diagnosed, job_id="j"))
    again = run(s.save("t", "c", later, job_id="j"))
    assert again.action == "deduped" and again.id == first.id
    got = run(s.get("t", first.id))
    assert got and got.history == []  # no churn recorded for an identical result
