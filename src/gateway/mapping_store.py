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
              materialization_class TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mappings_session_fp ON mappings(session_id, kind, subtype, fingerprint, state);
            """
        )
        self.conn.commit()

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
        ttl_seconds: int = 3600,
        max_ttl_seconds: int = 86_400,
        policy_hash: str = "default",
    ) -> MappingRecord:
        now = int(time.time())
        fingerprint = hashlib.sha256((kind + ":" + subtype + ":" + (value or "")).encode("utf-8")).hexdigest()
        with self._lock, self.conn:
            existing = self.conn.execute(
                "SELECT * FROM mappings WHERE session_id=? AND kind=? AND subtype=? AND fingerprint=? AND state='active'",
                (session_id, kind, subtype, fingerprint),
            ).fetchone()
            if existing:
                idle = min(int(existing["max_expires_at"]), now + ttl_seconds)
                self.conn.execute(
                    "UPDATE mappings SET last_seen_at=?, idle_expires_at=? WHERE handle_id=?",
                    (now, idle, existing["handle_id"]),
                )
                return self.get(existing["handle_id"])  # type: ignore[arg-type]
            handle_id = f"{kind[:4]}_{uuid.uuid4().hex[:10]}"
            record_value = value if store_value else None
            self.conn.execute(
                """
                INSERT INTO mappings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    now + ttl_seconds,
                    now + max_ttl_seconds,
                    "active",
                    policy_hash,
                    materialization_class,
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
        now = int(time.time())
        query = (
            "SELECT value FROM mappings "
            "WHERE session_id=? AND workspace_id=? AND state='active' "
            "AND value IS NOT NULL AND idle_expires_at>=? AND max_expires_at>=?"
        )
        params: list[Any] = [session_id, workspace_id, now, now]
        if materialization_class is not None:
            query += " AND materialization_class=?"
            params.append(materialization_class)
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        return [str(row["value"]) for row in rows if row["value"]]

    def active_path_values(self, session_id: str, workspace_id: str) -> list[str]:
        return self.active_values(session_id, workspace_id, materialization_class="path")

    def validate_active(self, handle_id: str, session_id: str, workspace_id: str) -> tuple[bool, MappingRecord | None, str]:
        now = int(time.time())
        with self._lock, self.conn:
            rec = self.get(handle_id)
            if not rec:
                return False, None, "APG_PLACEHOLDER_UNRESOLVED"
            # Check tombstone state BEFORE scope check — tombstoned records
            # have their metadata cleared and would spuriously fail scope check
            if rec.state == "tombstoned":
                return False, rec, "APG_PLACEHOLDER_TOMBSTONED"
            if rec.session_id != session_id or rec.workspace_id != workspace_id:
                return False, rec, "APG_PLACEHOLDER_SCOPE_MISMATCH"
            if rec.state != "active" or rec.idle_expires_at < now or rec.max_expires_at < now:
                self.conn.execute("UPDATE mappings SET state='tombstoned', value=NULL WHERE handle_id=?", (handle_id,))
                return False, rec, "APG_PLACEHOLDER_EXPIRED"
            # Extend idle expiry by the original TTL, capped at max_expires_at
            original_ttl = rec.idle_expires_at - rec.created_at if rec.created_at > 0 else 3600
            new_idle = min(rec.max_expires_at, now + max(original_ttl, 60))
            self.conn.execute(
                "UPDATE mappings SET last_seen_at=?, idle_expires_at=? WHERE handle_id=?",
                (now, new_idle, handle_id),
            )
        return True, self.get(handle_id), "OK"

    def tombstone(self, handle_id: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE mappings SET state='tombstoned', value=NULL, session_id='', workspace_id='', fingerprint='' WHERE handle_id=?",
                (handle_id,),
            )

    def expire_request_scope(self) -> int:
        now = int(time.time())
        with self._lock, self.conn:
            cur = self.conn.execute("UPDATE mappings SET state='tombstoned', value=NULL WHERE scope='request' AND idle_expires_at < ? AND state='active'", (now,))
            return cur.rowcount

    def tombstone_expired(self) -> int:
        now = int(time.time())
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE mappings SET state='tombstoned', value=NULL "
                "WHERE state='active' AND (idle_expires_at < ? OR max_expires_at < ?)",
                (now, now),
            )
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self.conn.close()


def _row_to_record(row: sqlite3.Row) -> MappingRecord:
    return MappingRecord(**{k: row[k] for k in row.keys()})
