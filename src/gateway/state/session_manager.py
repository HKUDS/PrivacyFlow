from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from pathlib import Path


class SessionManager:
    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
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
        if requested_session_id:
            row = self.conn.execute("SELECT * FROM sessions WHERE session_id=? AND state='active'", (requested_session_id,)).fetchone()
            if row:
                self.conn.execute("UPDATE sessions SET last_seen_at=?, expires_at=? WHERE session_id=?", (now, now + ttl_seconds, requested_session_id))
                self.conn.commit()
                return requested_session_id
        fp = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        row = self.conn.execute("SELECT * FROM sessions WHERE key_fingerprint=? AND state='active'", (fp,)).fetchone()
        if row:
            self.conn.execute("UPDATE sessions SET last_seen_at=?, expires_at=? WHERE session_id=?", (now, now + ttl_seconds, row["session_id"]))
            self.conn.commit()
            return str(row["session_id"])
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        self.conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, 'active')", (session_id, fp, now, now, now + ttl_seconds))
        self.conn.commit()
        return session_id
