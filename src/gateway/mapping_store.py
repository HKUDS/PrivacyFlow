from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MappingRecord:
    handle_id: str
    session_id: str
    workspace_id: str
    scope: str
    kind: str
    subtype: str
    value: str | None
    fingerprint: str
    created_at: int
    last_seen_at: int
    idle_expires_at: int
    max_expires_at: int
    state: str
    policy_hash: str
    materialization_class: str
    tombstone_reason: str


@dataclass(frozen=True)
class MappingRetentionPolicy:
    workspace_id: str
    enabled: bool
    idle_ttl_seconds: int
    revision: int
    updated_at: int


class MappingRetentionConflictError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditOperationRecord:
    id: int
    request_id: str
    session_id: str
    workspace_id: str
    endpoint: str
    timestamp: int
    direction: str
    handle_id: str
    kind: str
    subtype: str
    risk: str
    detector: str
    action: str
    sink: str
    result_code: str
    representation_type: str
    placeholder_session_id: str
    issued_at: int
    suffix: str
    alias: str
    tool_name: str
    occurrence_count: int


class MappingStore:
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init()
        # The mapping store now holds raw secret values (necessary for the
        # transparent tool-call materialization contract). Tighten the file
        # permissions; callers are responsible for placing the database in a
        # protected directory and, where appropriate, using disk encryption.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS mappings (
              handle_id TEXT PRIMARY KEY,
              session_id TEXT NOT NULL,
              workspace_id TEXT NOT NULL,
              scope TEXT NOT NULL,
              kind TEXT NOT NULL,
              subtype TEXT NOT NULL,
              value TEXT,
              fingerprint TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              last_seen_at INTEGER NOT NULL,
              idle_expires_at INTEGER NOT NULL,
              max_expires_at INTEGER NOT NULL,
              state TEXT NOT NULL,
              policy_hash TEXT NOT NULL,
              materialization_class TEXT NOT NULL,
              tombstone_reason TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_mappings_session_fp ON mappings(session_id, kind, subtype, fingerprint, state);

            CREATE TABLE IF NOT EXISTS audit_operations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              request_id TEXT NOT NULL,
              session_id TEXT NOT NULL,
              workspace_id TEXT NOT NULL,
              endpoint TEXT NOT NULL,
              timestamp INTEGER NOT NULL,
              direction TEXT NOT NULL,
              handle_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              subtype TEXT NOT NULL,
              risk TEXT NOT NULL,
              detector TEXT NOT NULL,
              action TEXT NOT NULL,
              sink TEXT NOT NULL,
              result_code TEXT NOT NULL,
              representation_type TEXT NOT NULL,
              placeholder_session_id TEXT NOT NULL,
              issued_at INTEGER NOT NULL,
              suffix TEXT NOT NULL,
              alias TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              occurrence_count INTEGER NOT NULL,
              UNIQUE (
                request_id, workspace_id, direction, handle_id, kind, subtype,
                risk, detector, action, sink, result_code,
                representation_type, placeholder_session_id, issued_at, suffix, alias, tool_name
              )
            );
            CREATE INDEX IF NOT EXISTS idx_audit_operations_request ON audit_operations(workspace_id, request_id, id);

            CREATE TABLE IF NOT EXISTS audit_operation_stats (
              workspace_id TEXT NOT NULL,
              request_id TEXT NOT NULL,
              omitted_count INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (workspace_id, request_id)
            );

            CREATE TABLE IF NOT EXISTS mapping_retention_policies (
              workspace_id TEXT PRIMARY KEY,
              enabled INTEGER NOT NULL,
              idle_ttl_seconds INTEGER NOT NULL,
              revision INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );
            """
        )
        mapping_columns = {str(row["name"]) for row in self.conn.execute("PRAGMA table_info(mappings)").fetchall()}
        if "tombstone_reason" not in mapping_columns:
            self.conn.execute("ALTER TABLE mappings ADD COLUMN tombstone_reason TEXT NOT NULL DEFAULT ''")
        now = int(time.time())
        self.conn.execute(
            """
            INSERT OR IGNORE INTO mapping_retention_policies (
              workspace_id, enabled, idle_ttl_seconds, revision, updated_at
            )
            SELECT DISTINCT workspace_id, 0, 86400, 0, ? FROM mappings WHERE workspace_id<>''
            """,
            (now,),
        )
        self.conn.execute(
            """
            UPDATE mappings SET idle_expires_at=0, max_expires_at=0
            WHERE state='active' AND workspace_id IN (
              SELECT workspace_id FROM mapping_retention_policies WHERE enabled=0
            )
            """
        )
        self.conn.commit()

    def mapping_retention_policy(self, workspace_id: str) -> MappingRetentionPolicy:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM mapping_retention_policies WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
            if row is None:
                now = int(time.time())
                self.conn.execute(
                    """
                    INSERT INTO mapping_retention_policies (
                      workspace_id, enabled, idle_ttl_seconds, revision, updated_at
                    ) VALUES (?, 0, 86400, 0, ?)
                    """,
                    (workspace_id, now),
                )
                self.conn.execute(
                    "UPDATE mappings SET idle_expires_at=0, max_expires_at=0 WHERE workspace_id=? AND state='active'",
                    (workspace_id,),
                )
                row = self.conn.execute(
                    "SELECT * FROM mapping_retention_policies WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()
        assert row is not None
        return _row_to_retention_policy(row)

    def set_mapping_retention_policy(
        self,
        *,
        workspace_id: str,
        enabled: bool,
        idle_ttl_seconds: int,
        expected_revision: int,
    ) -> MappingRetentionPolicy:
        if idle_ttl_seconds < 1 or idle_ttl_seconds > 365 * 86_400:
            raise ValueError("Mapping retention duration is out of range")
        now = int(time.time())
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM mapping_retention_policies WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
            current_revision = int(row["revision"]) if row is not None else 0
            if expected_revision != current_revision:
                raise MappingRetentionConflictError("Mapping retention policy revision conflict")
            revision = current_revision + 1
            self.conn.execute(
                """
                INSERT INTO mapping_retention_policies (
                  workspace_id, enabled, idle_ttl_seconds, revision, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id) DO UPDATE SET
                  enabled=excluded.enabled,
                  idle_ttl_seconds=excluded.idle_ttl_seconds,
                  revision=excluded.revision,
                  updated_at=excluded.updated_at
                """,
                (workspace_id, int(enabled), idle_ttl_seconds, revision, now),
            )
            if enabled:
                self.conn.execute(
                    """
                    UPDATE mappings SET idle_expires_at=?, max_expires_at=0
                    WHERE workspace_id=? AND state='active'
                    """,
                    (now + idle_ttl_seconds, workspace_id),
                )
            else:
                self.conn.execute(
                    """
                    UPDATE mappings SET idle_expires_at=0, max_expires_at=0
                    WHERE workspace_id=? AND state='active'
                    """,
                    (workspace_id,),
                )
            updated = self.conn.execute(
                "SELECT * FROM mapping_retention_policies WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
        assert updated is not None
        return _row_to_retention_policy(updated)

    def upsert_mapping(
        self,
        *,
        session_id: str,
        workspace_id: str,
        scope: str,
        kind: str,
        subtype: str,
        value: str | None,
        store_value: bool,
        materialization_class: str,
        ttl_seconds: int | None = None,
        max_ttl_seconds: int | None = None,
        policy_hash: str = "default",
    ) -> MappingRecord:
        now = int(time.time())
        retention = self.mapping_retention_policy(workspace_id)
        fingerprint = hashlib.sha256((kind + ":" + subtype + ":" + (value or "")).encode("utf-8")).hexdigest()
        with self._lock, self.conn:
            existing = self.conn.execute(
                "SELECT * FROM mappings WHERE session_id=? AND kind=? AND subtype=? AND fingerprint=? AND state='active'",
                (session_id, kind, subtype, fingerprint),
            ).fetchone()
            if existing:
                if retention.enabled:
                    idle = now + retention.idle_ttl_seconds
                    maximum = 0
                elif ttl_seconds is None:
                    idle = 0
                    maximum = 0
                else:
                    maximum = int(existing["max_expires_at"] or 0)
                    if maximum <= 0:
                        maximum = now + (max_ttl_seconds if max_ttl_seconds is not None else 86_400)
                    idle = min(maximum, now + ttl_seconds)
                self.conn.execute(
                    "UPDATE mappings SET last_seen_at=?, idle_expires_at=?, max_expires_at=? WHERE handle_id=?",
                    (now, idle, maximum, existing["handle_id"]),
                )
                return self.get(existing["handle_id"])  # type: ignore[arg-type]
            handle_id = f"{kind[:4]}_{uuid.uuid4().hex[:10]}"
            record_value = value if store_value else None
            if retention.enabled:
                idle_expires_at = now + retention.idle_ttl_seconds
                max_expires_at = 0
            elif ttl_seconds is None:
                idle_expires_at = 0
                max_expires_at = 0
            else:
                idle_expires_at = now + ttl_seconds
                max_expires_at = now + (max_ttl_seconds if max_ttl_seconds is not None else 86_400)
            self.conn.execute(
                """
                INSERT INTO mappings (
                  handle_id, session_id, workspace_id, scope, kind, subtype,
                  value, fingerprint, created_at, last_seen_at, idle_expires_at,
                  max_expires_at, state, policy_hash, materialization_class, tombstone_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    handle_id,
                    session_id,
                    workspace_id,
                    scope,
                    kind,
                    subtype,
                    record_value,
                    fingerprint,
                    now,
                    now,
                    idle_expires_at,
                    max_expires_at,
                    "active",
                    policy_hash,
                    materialization_class,
                    "",
                ),
            )
        return self.get(handle_id)

    def get(self, handle_id: str) -> MappingRecord | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM mappings WHERE handle_id=?", (handle_id,)).fetchone()
        return _row_to_record(row) if row else None

    def list_records(
        self,
        *,
        workspace_id: str | None = None,
        state: str | None = None,
        kind: str | None = None,
        limit: int = 500,
    ) -> list[MappingRecord]:
        """List mapping metadata for local administration.

        Callers must never serialize ``value``, ``fingerprint``, or
        ``handle_id`` directly. The WebUI control plane converts each record
        into an opaque administration id before returning it.
        """
        query = "SELECT * FROM mappings WHERE 1=1"
        params: list[Any] = []
        if workspace_id is not None:
            query += " AND workspace_id=?"
            params.append(workspace_id)
        if state is not None:
            query += " AND state=?"
            params.append(state)
        if kind is not None:
            query += " AND kind=?"
            params.append(kind)
        query += " ORDER BY last_seen_at DESC LIMIT ?"
        params.append(max(1, min(limit, 2000)))
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [_row_to_record(row) for row in rows]

    def active_values(
        self,
        session_id: str,
        workspace_id: str,
        *,
        materialization_class: str | None = None,
    ) -> list[str]:
        """Return live local values for cross-delta response protection.

        This is deliberately a read-only lookup: it does not refresh mapping
        lifetimes and never exposes values outside the owning session and
        workspace.
        """
        return [record.value for record in self.active_records(
            session_id,
            workspace_id,
            materialization_class=materialization_class,
        ) if record.value]

    def active_records(
        self,
        session_id: str,
        workspace_id: str,
        *,
        materialization_class: str | None = None,
    ) -> list[MappingRecord]:
        now = int(time.time())
        query = (
            "SELECT * FROM mappings "
            "WHERE session_id=? AND workspace_id=? AND state='active' "
            "AND value IS NOT NULL "
            "AND (idle_expires_at=0 OR idle_expires_at>=?) "
            "AND (max_expires_at=0 OR max_expires_at>=?)"
        )
        params: list[Any] = [session_id, workspace_id, now, now]
        if materialization_class is not None:
            query += " AND materialization_class=?"
            params.append(materialization_class)
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [_row_to_record(row) for row in rows]

    def active_path_values(self, session_id: str, workspace_id: str) -> list[str]:
        return self.active_values(session_id, workspace_id, materialization_class="path")

    def record_audit_operations(
        self,
        *,
        request_id: str,
        session_id: str,
        workspace_id: str,
        endpoint: str,
        timestamp: int,
        operations: list[dict[str, Any]],
        max_unique: int = 1000,
    ) -> None:
        if not request_id or not operations:
            return
        with self._lock, self.conn:
            for operation in operations:
                normalized = _normalize_audit_operation(operation)
                if normalized is None:
                    continue
                values = (
                    request_id,
                    session_id,
                    workspace_id,
                    endpoint,
                    timestamp,
                    *normalized,
                )
                unique_values = (
                    request_id,
                    workspace_id,
                    *normalized,
                )
                existing = self.conn.execute(
                    """
                    SELECT id FROM audit_operations
                    WHERE request_id=? AND workspace_id=? AND direction=? AND handle_id=?
                      AND kind=? AND subtype=? AND risk=? AND detector=? AND action=?
                      AND sink=? AND result_code=? AND representation_type=?
                      AND placeholder_session_id=? AND issued_at=? AND suffix=? AND alias=? AND tool_name=?
                    """,
                    unique_values[:-1],
                ).fetchone()
                occurrence_count = normalized[-1]
                if existing:
                    self.conn.execute(
                        "UPDATE audit_operations SET occurrence_count=occurrence_count+? WHERE id=?",
                        (occurrence_count, int(existing["id"])),
                    )
                    continue
                count = int(
                    self.conn.execute(
                        "SELECT COUNT(*) FROM audit_operations WHERE request_id=? AND workspace_id=?",
                        (request_id, workspace_id),
                    ).fetchone()[0]
                )
                if count >= max_unique:
                    self.conn.execute(
                        """
                        INSERT INTO audit_operation_stats (workspace_id, request_id, omitted_count)
                        VALUES (?, ?, ?)
                        ON CONFLICT(workspace_id, request_id)
                        DO UPDATE SET omitted_count=omitted_count+excluded.omitted_count
                        """,
                        (workspace_id, request_id, occurrence_count),
                    )
                    continue
                self.conn.execute(
                    """
                    INSERT INTO audit_operations (
                      request_id, session_id, workspace_id, endpoint, timestamp,
                      direction, handle_id, kind, subtype, risk, detector, action,
                      sink, result_code, representation_type, placeholder_session_id, issued_at, suffix,
                      alias, tool_name, occurrence_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )

    def audit_operations_for_request(self, request_id: str, workspace_id: str) -> list[AuditOperationRecord]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM audit_operations WHERE request_id=? AND workspace_id=? ORDER BY id",
                (request_id, workspace_id),
            ).fetchall()
        return [_row_to_audit_operation(row) for row in rows]

    def list_audit_operations(
        self,
        *,
        workspace_id: str,
        direction: str,
        query: str = "",
        risk: str = "",
        endpoint: str = "",
        limit: int = 250,
    ) -> tuple[list[AuditOperationRecord], int, int]:
        directions = _audit_directions(direction)
        direction_placeholders = ",".join("?" for _ in directions)
        clauses = ["workspace_id=?", f"direction IN ({direction_placeholders})"]
        params: list[Any] = [workspace_id, *directions]
        if risk:
            clauses.append("risk=?")
            params.append(risk)
        if endpoint:
            clauses.append("endpoint=?")
            params.append(endpoint)
        if query.strip():
            clauses.append(
                "LOWER(request_id || ' ' || session_id || ' ' || endpoint || ' ' || kind || ' ' || "
                "subtype || ' ' || detector || ' ' || action || ' ' || sink || ' ' || result_code || ' ' || tool_name) LIKE ?"
            )
            params.append(f"%{query.strip().lower()}%")
        where = " AND ".join(clauses)
        bounded_limit = max(1, min(limit, 500))
        with self._lock:
            aggregate = self.conn.execute(
                f"SELECT COUNT(*) AS unique_count, COALESCE(SUM(occurrence_count), 0) AS occurrence_count "
                f"FROM audit_operations WHERE {where}",
                params,
            ).fetchone()
            rows = self.conn.execute(
                f"SELECT * FROM audit_operations WHERE {where} ORDER BY timestamp DESC, id DESC LIMIT ?",
                (*params, bounded_limit),
            ).fetchall()
        return (
            [_row_to_audit_operation(row) for row in rows],
            int(aggregate["unique_count"] or 0),
            int(aggregate["occurrence_count"] or 0),
        )

    def audit_operation_filter_values(self, workspace_id: str, direction: str) -> dict[str, list[str]]:
        directions = _audit_directions(direction)
        placeholders = ",".join("?" for _ in directions)
        params = (workspace_id, *directions)
        with self._lock:
            endpoints = self.conn.execute(
                f"SELECT DISTINCT endpoint FROM audit_operations "
                f"WHERE workspace_id=? AND direction IN ({placeholders}) AND endpoint<>'' ORDER BY endpoint",
                params,
            ).fetchall()
            risks = self.conn.execute(
                f"SELECT DISTINCT risk FROM audit_operations "
                f"WHERE workspace_id=? AND direction IN ({placeholders}) AND risk<>''",
                params,
            ).fetchall()
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return {
            "endpoints": [str(row["endpoint"]) for row in endpoints],
            "risks": sorted((str(row["risk"]) for row in risks), key=lambda value: (risk_order.get(value, 99), value)),
        }

    def audit_operation_counts(self, request_ids: list[str], workspace_id: str) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        unique_ids = list(dict.fromkeys(request_id for request_id in request_ids if request_id))
        for offset in range(0, len(unique_ids), 400):
            batch = unique_ids[offset:offset + 400]
            placeholders = ",".join("?" for _ in batch)
            if not placeholders:
                continue
            with self._lock:
                rows = self.conn.execute(
                    f"""
                    SELECT request_id, direction, COUNT(*) AS unique_count,
                           SUM(occurrence_count) AS occurrence_count
                    FROM audit_operations
                    WHERE workspace_id=? AND request_id IN ({placeholders})
                    GROUP BY request_id, direction
                    """,
                    (workspace_id, *batch),
                ).fetchall()
                omitted_rows = self.conn.execute(
                    f"""
                    SELECT request_id, omitted_count FROM audit_operation_stats
                    WHERE workspace_id=? AND request_id IN ({placeholders})
                    """,
                    (workspace_id, *batch),
                ).fetchall()
            for row in rows:
                summary = counts.setdefault(str(row["request_id"]), {})
                direction = str(row["direction"])
                summary[f"{direction}_unique"] = int(row["unique_count"] or 0)
                summary[f"{direction}_count"] = int(row["occurrence_count"] or 0)
            for row in omitted_rows:
                counts.setdefault(str(row["request_id"]), {})["omitted_count"] = int(row["omitted_count"] or 0)
        return counts

    def audit_operation_omitted_count(self, request_id: str, workspace_id: str) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT omitted_count FROM audit_operation_stats WHERE workspace_id=? AND request_id=?",
                (workspace_id, request_id),
            ).fetchone()
        return int(row["omitted_count"] or 0) if row else 0

    def validate_active(self, handle_id: str, session_id: str, workspace_id: str) -> tuple[bool, MappingRecord | None, str]:
        now = int(time.time())
        with self._lock, self.conn:
            rec = self.get(handle_id)
            if not rec:
                return False, None, "APG_PLACEHOLDER_UNRESOLVED"
            # Check tombstone state BEFORE scope check — tombstoned records
            # have their metadata cleared and would spuriously fail scope check
            if rec.state == "tombstoned":
                code = "APG_PLACEHOLDER_EXPIRED" if rec.tombstone_reason == "expired" else "APG_PLACEHOLDER_TOMBSTONED"
                return False, rec, code
            if rec.session_id != session_id or rec.workspace_id != workspace_id:
                return False, rec, "APG_PLACEHOLDER_SCOPE_MISMATCH"
            expired = (
                (rec.idle_expires_at > 0 and rec.idle_expires_at < now)
                or (rec.max_expires_at > 0 and rec.max_expires_at < now)
            )
            if rec.state != "active" or expired:
                self.conn.execute(
                    "UPDATE mappings SET state='tombstoned', value=NULL, tombstone_reason='expired' WHERE handle_id=?",
                    (handle_id,),
                )
                return False, rec, "APG_PLACEHOLDER_EXPIRED"
            retention = self.mapping_retention_policy(workspace_id)
            if retention.enabled:
                new_idle = now + retention.idle_ttl_seconds
            elif rec.idle_expires_at > 0:
                original_ttl = rec.idle_expires_at - rec.created_at if rec.created_at > 0 else 3600
                candidate = now + max(original_ttl, 60)
                new_idle = min(rec.max_expires_at, candidate) if rec.max_expires_at > 0 else candidate
            else:
                new_idle = 0
            self.conn.execute(
                "UPDATE mappings SET last_seen_at=?, idle_expires_at=? WHERE handle_id=?",
                (now, new_idle, handle_id),
            )
        return True, self.get(handle_id), "OK"

    def tombstone(self, handle_id: str, *, reason: str = "revoked") -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """
                UPDATE mappings SET state='tombstoned', value=NULL, session_id='', workspace_id='',
                  fingerprint='', tombstone_reason=? WHERE handle_id=?
                """,
                (reason, handle_id),
            )

    def expire_request_scope(self) -> int:
        now = int(time.time())
        with self._lock, self.conn:
            cur = self.conn.execute(
                """
                UPDATE mappings SET state='tombstoned', value=NULL, tombstone_reason='expired'
                WHERE scope='request' AND idle_expires_at>0 AND idle_expires_at < ? AND state='active'
                """,
                (now,),
            )
            return cur.rowcount

    def tombstone_expired(self) -> int:
        now = int(time.time())
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE mappings SET state='tombstoned', value=NULL, tombstone_reason='expired' "
                "WHERE state='active' AND ("
                "  (idle_expires_at>0 AND idle_expires_at < ?) "
                "  OR (max_expires_at>0 AND max_expires_at < ?)"
                ")",
                (now, now),
            )
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self.conn.close()


def _row_to_record(row: sqlite3.Row) -> MappingRecord:
    return MappingRecord(**{k: row[k] for k in row.keys()})


def _row_to_retention_policy(row: sqlite3.Row) -> MappingRetentionPolicy:
    return MappingRetentionPolicy(
        workspace_id=str(row["workspace_id"]),
        enabled=bool(row["enabled"]),
        idle_ttl_seconds=int(row["idle_ttl_seconds"]),
        revision=int(row["revision"]),
        updated_at=int(row["updated_at"]),
    )


def _row_to_audit_operation(row: sqlite3.Row) -> AuditOperationRecord:
    return AuditOperationRecord(**{k: row[k] for k in row.keys()})


def _normalize_audit_operation(operation: dict[str, Any]) -> tuple[Any, ...] | None:
    direction = str(operation.get("direction") or "")[:32]
    handle_id = str(operation.get("handle_id") or "")[:128]
    if direction not in {"replacement", "materialization", "materialization_failed"} or not handle_id:
        return None
    occurrence_count = max(1, min(int(operation.get("occurrence_count", 1) or 1), 1_000_000))
    return (
        direction,
        handle_id,
        str(operation.get("kind") or "")[:64],
        str(operation.get("subtype") or "")[:128],
        str(operation.get("risk") or "")[:32],
        str(operation.get("detector") or "")[:256],
        str(operation.get("action") or "")[:64],
        str(operation.get("sink") or "")[:64],
        str(operation.get("result_code") or "")[:128],
        str(operation.get("representation_type") or "")[:64],
        str(operation.get("placeholder_session_id") or "")[:256],
        max(0, int(operation.get("issued_at", 0) or 0)),
        str(operation.get("suffix") or "")[:4096],
        str(operation.get("alias") or "")[:4096],
        str(operation.get("tool_name") or "")[:512],
        occurrence_count,
    )


def _audit_directions(direction: str) -> tuple[str, ...]:
    if direction == "replacement":
        return ("replacement",)
    if direction == "materialization":
        return ("materialization", "materialization_failed")
    raise ValueError("Unsupported audit operation direction")
