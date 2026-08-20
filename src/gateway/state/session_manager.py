from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
import uuid
from pathlib import Path


class SessionScopeError(RuntimeError):
    code = "PF_SESSION_SCOPE_MISMATCH"


class SessionManager:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.RLock()
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
              session_id TEXT PRIMARY KEY,
              key_fingerprint TEXT NOT NULL UNIQUE,
              created_at INTEGER NOT NULL,
              last_seen_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              state TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def session_for_key(self, api_key: str, requested_session_id: str | None = None, ttl_seconds: int = 7 * 86_400) -> str:
        now = int(time.time())
        fp = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with self._lock, self.conn:
            if requested_session_id:
                row = self.conn.execute("SELECT * FROM sessions WHERE session_id=?", (requested_session_id,)).fetchone()
                if row is None or row["key_fingerprint"] != fp or row["state"] != "active" or int(row["expires_at"]) < now:
                    if row is not None and int(row["expires_at"]) < now:
                        self.conn.execute("UPDATE sessions SET state='expired' WHERE session_id=?", (requested_session_id,))
                    raise SessionScopeError("Requested session is unavailable for this local API key")
                self.conn.execute(
                    "UPDATE sessions SET last_seen_at=?, expires_at=? WHERE session_id=?",
                    (now, now + ttl_seconds, requested_session_id),
                )
                return requested_session_id

            row = self.conn.execute("SELECT * FROM sessions WHERE key_fingerprint=?", (fp,)).fetchone()
            if row is not None and row["state"] == "active" and int(row["expires_at"]) >= now:
                self.conn.execute(
                    "UPDATE sessions SET last_seen_at=?, expires_at=? WHERE session_id=?",
                    (now, now + ttl_seconds, row["session_id"]),
                )
                return str(row["session_id"])

            session_id = f"sess_{uuid.uuid4().hex[:12]}"
            if row is None:
                self.conn.execute(
                    "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, 'active')",
                    (session_id, fp, now, now, now + ttl_seconds),
                )
            else:
                self.conn.execute(
                    "UPDATE sessions SET session_id=?, created_at=?, last_seen_at=?, expires_at=?, state='active' WHERE key_fingerprint=?",
                    (session_id, now, now, now + ttl_seconds, fp),
                )
            return session_id

    def expire_sessions(self) -> int:
        now = int(time.time())
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE sessions SET state='expired' WHERE state='active' AND expires_at < ?",
                (now,),
            )
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self.conn.close()
