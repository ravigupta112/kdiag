"""Bounded report history on SQLite (stdlib). SQL is kept portable so Postgres can follow.

Guarantees: every query is tenant-scoped; only masked reports are stored and a final secret scan
refuses to persist anything sensitive-looking; bodies are size-capped; history is bounded by age,
count per target and rows per tenant; corrupt or too-new bodies are reported as unreadable instead
of breaking readers; one row per (tenant, cluster, job) with best-diagnosis-wins merging.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import ValidationError

from .mask import contains_secret, mask_text
from .models import SCHEMA_VERSION, DiagnosisReport
from .observability import NULL_METRICS, Metrics

# (version, statements). Never edit a shipped migration; append a new one.
MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (1, (
        """CREATE TABLE reports (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, cluster_id TEXT NOT NULL,
            namespace TEXT, target_kind TEXT, target_name TEXT, job_id TEXT,
            schema_version INTEGER NOT NULL, status TEXT NOT NULL, primary_rule TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            body_sha256 TEXT NOT NULL, body TEXT NOT NULL)""",
    )),
    (2, (
        "ALTER TABLE reports ADD COLUMN history TEXT NOT NULL DEFAULT '[]'",
        "CREATE UNIQUE INDEX uq_reports_job ON reports(tenant_id, cluster_id, job_id) WHERE job_id IS NOT NULL",
        "CREATE INDEX ix_reports_target ON reports(tenant_id, cluster_id, namespace, target_name, created_at)",
        "CREATE INDEX ix_reports_created ON reports(created_at)",
    )),
)
LATEST = MIGRATIONS[-1][0]
MAX_HISTORY = 5


class PersistRefused(Exception):
    """The report looked sensitive or could not be shrunk under the size cap; nothing was stored."""


@dataclass(frozen=True)
class RetentionPolicy:
    max_age_days: int = 30
    max_per_target: int = 50
    max_rows_per_tenant: int = 10_000


@dataclass(frozen=True)
class SaveResult:
    id: str
    action: Literal["created", "replaced", "kept", "deduped"]
    size_bytes: int
    shrunk: bool = False


@dataclass(frozen=True)
class StoredSummary:
    id: str
    cluster_id: str
    namespace: str | None
    target_kind: str | None
    target_name: str | None
    job_id: str | None
    status: str
    primary_rule: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class StoredReport:
    summary: StoredSummary
    report: DiagnosisReport | None
    unreadable: str | None = None  # "corrupt" | "newer_schema" | "invalid"
    history: list[dict[str, Any]] = field(default_factory=list)


def migrate(conn: sqlite3.Connection, target: int | None = None) -> int:
    """Apply pending migrations in order, each atomically. Safe to run repeatedly."""
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
    current = int(row[0])
    for version, statements in MIGRATIONS:
        if version <= current or (target is not None and version > target):
            continue
        # sqlite3 does not open a transaction for DDL on its own, so begin explicitly: a failed
        # migration must leave no half-applied schema behind (SQLite DDL is transactional).
        conn.execute("BEGIN")
        try:
            for stmt in statements:
                conn.execute(stmt)
            conn.execute("INSERT INTO schema_migrations VALUES (?, ?)", (version, datetime.now(UTC).isoformat()))
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        current = version
    return current


def upgrade_report(doc: dict[str, Any]) -> dict[str, Any]:
    """Bring an older stored report dict up to the current schema. v1 is current: identity."""
    return doc


def _content_hash(body: str) -> str:
    """Hash of the report *content*: the collection timestamp is excluded so re-running the same
    diagnosis is recognised as a duplicate instead of a new version."""
    doc = json.loads(body)
    doc.pop("collected_at", None)
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def _score(r: DiagnosisReport) -> int:
    """How informative a report is about a failure. Higher wins when merging by job."""
    if r.status == "diagnosed":
        return 5
    if r.status == "partial":
        return 4 if r.primary else 3
    if r.status in ("unknown", "ambiguous_target"):
        return 2
    if r.status == "no_issue_detected":
        return 1
    return 0


def _shrink(report: DiagnosisReport, cap: int) -> tuple[str, bool]:
    body = report.model_dump_json()
    if len(body.encode()) <= cap:
        return body, False
    trimmed = report.model_copy(update={"supporting": (), "notes": (), "skipped_rules": (), "truncated": True})
    body = trimmed.model_dump_json()
    if len(body.encode()) <= cap:
        return body, True
    if trimmed.primary:  # keep only a short primary
        p = trimmed.primary.model_copy(update={
            "summary": trimmed.primary.summary[:200], "next_action": trimmed.primary.next_action[:200],
            "details": {}, "evidence_refs": trimmed.primary.evidence_refs[:3]})
        trimmed = trimmed.model_copy(update={"primary": p, "partial_errors": trimmed.partial_errors[:5],
                                             "candidates": trimmed.candidates[:5]})
        body = trimmed.model_dump_json()
        if len(body.encode()) <= cap:
            return body, True
    raise PersistRefused("report cannot be reduced under the size cap")


def _summary(row: sqlite3.Row) -> StoredSummary:
    return StoredSummary(
        id=row["id"], cluster_id=row["cluster_id"], namespace=row["namespace"],
        target_kind=row["target_kind"], target_name=row["target_name"], job_id=row["job_id"],
        status=row["status"], primary_rule=row["primary_rule"], created_at=row["created_at"],
        updated_at=row["updated_at"])


class SqliteStore:
    def __init__(self, path: str = ":memory:", *, max_report_bytes: int = 262_144,
                 retention: RetentionPolicy | None = None, metrics: Metrics | None = None) -> None:
        self._path, self._cap = path, max_report_bytes
        self._ret = retention or RetentionPolicy()
        self._m = metrics or NULL_METRICS
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        migrate(self._conn)

    async def _run(self, fn: Any, *a: Any) -> Any:
        def locked() -> Any:
            with self._lock:
                return fn(*a)
        return await asyncio.to_thread(locked)

    def close(self) -> None:
        self._conn.close()

    # ---- save --------------------------------------------------------------------------------

    async def save(self, tenant_id: str, cluster_id: str, report: DiagnosisReport,
                   job_id: str | None = None, now: datetime | None = None) -> SaveResult:
        try:
            res: SaveResult = await self._run(self._save, tenant_id, cluster_id, report, job_id,
                                              now or datetime.now(UTC))
        except PersistRefused:
            self._m.inc("kdiag_snapshot_total", result="refused")
            raise
        except Exception:
            self._m.inc("kdiag_snapshot_total", result="error")
            self._m.inc("kdiag_persistence_errors_total")
            raise
        self._m.inc("kdiag_snapshot_total", result=res.action)
        self._m.observe("kdiag_snapshot_bytes", float(res.size_bytes))
        return res

    def _save(self, tenant: str, cluster: str, report: DiagnosisReport, job_id: str | None,
              now: datetime) -> SaveResult:
        body, shrunk = _shrink(report, self._cap)
        if contains_secret(body):  # reports are masked already; refuse rather than persist a leak
            raise PersistRefused("report looks sensitive")
        sha = _content_hash(body)
        ts, size = now.isoformat(), len(body.encode())
        t = report.target
        primary = report.primary.rule_id if report.primary else None
        c = self._conn
        existing = None
        if job_id:
            existing = c.execute(
                "SELECT * FROM reports WHERE tenant_id=? AND cluster_id=? AND job_id=?",
                (tenant, cluster, job_id)).fetchone()
        if existing is None:
            rid = uuid.uuid4().hex
            with c:
                c.execute(
                    "INSERT INTO reports (id, tenant_id, cluster_id, namespace, target_kind, target_name, job_id,"
                    " schema_version, status, primary_rule, created_at, updated_at, size_bytes, body_sha256, body)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, tenant, cluster, t.namespace if t else None, t.kind if t else None,
                     t.name if t else None, job_id, report.schema_version, report.status, primary,
                     ts, ts, size, sha, body))
            return SaveResult(rid, "created", size, shrunk)

        rid = existing["id"]
        history: list[dict[str, Any]] = json.loads(existing["history"] or "[]")
        if existing["body_sha256"] == sha:
            with c:
                c.execute("UPDATE reports SET updated_at=? WHERE id=?", (ts, rid))
            return SaveResult(rid, "deduped", size, shrunk)
        old = self._parse(existing["body"])
        better = old is None or _score(report) >= _score(old)
        entry = {"status": report.status if not better else existing["status"],
                 "primary_rule": primary if not better else existing["primary_rule"],
                 "at": ts if not better else existing["updated_at"],
                 "outcome": "not_better" if not better else "superseded"}
        history = ([entry] + history)[:MAX_HISTORY]
        if not better:
            with c:
                c.execute("UPDATE reports SET history=? WHERE id=?", (json.dumps(history), rid))
            return SaveResult(rid, "kept", existing["size_bytes"], False)
        with c:
            c.execute(
                "UPDATE reports SET schema_version=?, status=?, primary_rule=?, updated_at=?, size_bytes=?,"
                " body_sha256=?, body=?, history=?, namespace=?, target_kind=?, target_name=? WHERE id=?",
                (report.schema_version, report.status, primary, ts, size, sha, body, json.dumps(history),
                 t.namespace if t else None, t.kind if t else None, t.name if t else None, rid))
        return SaveResult(rid, "replaced", size, shrunk)

    # ---- read --------------------------------------------------------------------------------

    @staticmethod
    def _parse(body: str) -> DiagnosisReport | None:
        try:
            doc = json.loads(body)
            if not isinstance(doc, dict):
                return None
            if int(doc.get("schema_version", 0)) > SCHEMA_VERSION:
                return None
            return DiagnosisReport.model_validate(upgrade_report(doc))
        except (ValueError, TypeError, ValidationError):
            return None

    async def get(self, tenant_id: str, report_id: str) -> StoredReport | None:
        def q() -> StoredReport | None:
            row = self._conn.execute("SELECT * FROM reports WHERE tenant_id=? AND id=?",
                                     (tenant_id, report_id)).fetchone()
            if row is None:
                return None
            report = self._parse(row["body"])
            reason: str | None = None
            if report is None:
                try:
                    newer = int(json.loads(row["body"]).get("schema_version", 0)) > SCHEMA_VERSION
                except (ValueError, TypeError, AttributeError):
                    newer = None
                reason = "corrupt" if newer is None else "newer_schema" if newer else "invalid"
            return StoredReport(_summary(row), report, reason, json.loads(row["history"] or "[]"))
        out: StoredReport | None = await self._run(q)
        if out and out.unreadable:
            self._m.inc("kdiag_snapshot_unreadable_total", reason=out.unreadable)
        return out

    async def list_for_target(self, tenant_id: str, cluster_id: str, namespace: str | None,
                              target_name: str, limit: int = 20) -> list[StoredSummary]:
        def q() -> list[StoredSummary]:
            rows = self._conn.execute(
                "SELECT * FROM reports WHERE tenant_id=? AND cluster_id=? AND target_name=?"
                " AND (? IS NULL OR namespace=?) ORDER BY created_at DESC LIMIT ?",
                (tenant_id, cluster_id, target_name, namespace, namespace, max(1, min(limit, 100)))).fetchall()
            return [_summary(r) for r in rows]
        out: list[StoredSummary] = await self._run(q)
        return out

    # ---- retention ---------------------------------------------------------------------------

    async def purge(self, now: datetime | None = None) -> int:
        def run() -> int:
            cutoff = ((now or datetime.now(UTC)) - timedelta(days=self._ret.max_age_days)).isoformat()
            total = 0
            with self._conn:
                total += self._conn.execute("DELETE FROM reports WHERE created_at < ?", (cutoff,)).rowcount
                total += self._conn.execute(
                    "DELETE FROM reports WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER ("
                    " PARTITION BY tenant_id, cluster_id, namespace, target_kind, target_name"
                    " ORDER BY created_at DESC) rn FROM reports) WHERE rn > ?)",
                    (self._ret.max_per_target,)).rowcount
                total += self._conn.execute(
                    "DELETE FROM reports WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER ("
                    " PARTITION BY tenant_id ORDER BY created_at DESC) rn FROM reports) WHERE rn > ?)",
                    (self._ret.max_rows_per_tenant,)).rowcount
            return total
        deleted: int = await self._run(run)
        self._m.inc("kdiag_retention_deleted_total", deleted)
        return deleted

    async def count(self, tenant_id: str | None = None) -> int:
        def q() -> int:
            if tenant_id is None:
                return int(self._conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0])
            return int(self._conn.execute("SELECT COUNT(*) FROM reports WHERE tenant_id=?",
                                          (tenant_id,)).fetchone()[0])
        n: int = await self._run(q)
        return n


__all__ = [
    "LATEST",
    "MIGRATIONS",
    "PersistRefused",
    "RetentionPolicy",
    "SaveResult",
    "SqliteStore",
    "StoredReport",
    "StoredSummary",
    "mask_text",
    "migrate",
    "upgrade_report",
]
