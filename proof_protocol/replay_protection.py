"""Replay protection — a TTL-bounded set of seen nonces / challenge IDs.

In production this would live in Redis or a CRDT. Here we use SQLite so it
survives restarts.
"""

from __future__ import annotations

import time

from .database import Database


REPLAY_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS replay_seen (
    key         TEXT PRIMARY KEY,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_replay_expires ON replay_seen(expires_at);
"""


class ReplayGuard:
    def __init__(self, db: Database):
        self._db = db
        with self._db._lock:
            # executescript() implicitly commits, so it must run outside tx()
            self._db._conn.executescript(REPLAY_TABLE_DDL)

    def seen_or_record(self, key: str, ttl_seconds: int = 300) -> bool:
        """Atomic check-and-insert. Returns True if ``key`` was already seen."""
        now = time.time()
        with self._db.tx() as c:
            c.execute("DELETE FROM replay_seen WHERE expires_at < ?", (now,))
            row = c.execute("SELECT 1 FROM replay_seen WHERE key=?", (key,)).fetchone()
            if row:
                return True
            c.execute("INSERT INTO replay_seen(key, expires_at) VALUES(?, ?)",
                      (key, now + ttl_seconds))
            return False

    def purge(self) -> int:
        with self._db.tx() as c:
            cur = c.execute("DELETE FROM replay_seen WHERE expires_at < ?", (time.time(),))
            return cur.rowcount
