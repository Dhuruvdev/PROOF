"""SQLite-backed persistence for the PROOF Network state.

Tracks issued tokens, validator records, revocations, reputation, and the
audit log. All writes are wrapped in transactions and use parameterised
queries.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    public_key       TEXT NOT NULL,
    enrolled_at      REAL NOT NULL,
    commitment       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_id         TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    tier             TEXT NOT NULL,
    issued_at        REAL NOT NULL,
    expires_at       REAL NOT NULL,
    proof_blob       TEXT NOT NULL,
    revoked          INTEGER NOT NULL DEFAULT 0,
    revoked_at       REAL,
    revoked_reason   TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS validators (
    validator_id     TEXT PRIMARY KEY,
    operator         TEXT NOT NULL,
    public_key       TEXT NOT NULL,
    region           TEXT NOT NULL,
    joined_at        REAL NOT NULL,
    active           INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS reputation (
    device_id        TEXT PRIMARY KEY,
    score            REAL NOT NULL DEFAULT 100.0,
    abuse_reports    INTEGER NOT NULL DEFAULT 0,
    successful_uses  INTEGER NOT NULL DEFAULT 0,
    last_updated     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               REAL NOT NULL,
    actor            TEXT NOT NULL,
    action           TEXT NOT NULL,
    detail           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verifications (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id         TEXT NOT NULL,
    requester        TEXT NOT NULL,
    ts               REAL NOT NULL,
    valid            INTEGER NOT NULL,
    quorum           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS premium_links (
    device_id        TEXT PRIMARY KEY,
    aadhaar_hash     TEXT,
    upi_handle       TEXT,
    digilocker_id    TEXT,
    linked_at        REAL NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(device_id)
);
"""


class Database:
    """Thread-safe SQLite wrapper. One connection per process; serialises writes."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL;")
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.executescript(SCHEMA)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE;")
                yield self._conn
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

    # --- audit -------------------------------------------------------------- #

    def log(self, actor: str, action: str, detail: dict[str, Any] | str = "") -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO audit_log(ts, actor, action, detail) VALUES (?,?,?,?)",
                (time.time(), actor, action, json.dumps(detail) if not isinstance(detail, str) else detail),
            )

    def recent_audit(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ))

    # --- devices ------------------------------------------------------------ #

    def upsert_device(self, device_id: str, public_key_hex: str, commitment_hex: str) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO devices(device_id, public_key, enrolled_at, commitment)
                   VALUES(?,?,?,?)
                   ON CONFLICT(device_id) DO UPDATE SET
                     public_key=excluded.public_key,
                     commitment=excluded.commitment""",
                (device_id, public_key_hex, time.time(), commitment_hex),
            )
            c.execute(
                """INSERT OR IGNORE INTO reputation(device_id, score, last_updated)
                   VALUES(?, 100.0, ?)""",
                (device_id, time.time()),
            )

    def get_device(self, device_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()

    def list_devices(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM devices ORDER BY enrolled_at DESC"))

    # --- tokens ------------------------------------------------------------- #

    def insert_token(
        self,
        token_id: str,
        device_id: str,
        tier: str,
        issued_at: float,
        expires_at: float,
        proof_blob: str,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO tokens(token_id, device_id, tier, issued_at, expires_at, proof_blob)
                   VALUES(?,?,?,?,?,?)""",
                (token_id, device_id, tier, issued_at, expires_at, proof_blob),
            )

    def get_token(self, token_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM tokens WHERE token_id=?", (token_id,)
            ).fetchone()

    def list_tokens(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(
                "SELECT * FROM tokens ORDER BY issued_at DESC"
            ))

    def revoke_token(self, token_id: str, reason: str) -> bool:
        with self.tx() as c:
            cur = c.execute(
                "UPDATE tokens SET revoked=1, revoked_at=?, revoked_reason=? WHERE token_id=? AND revoked=0",
                (time.time(), reason, token_id),
            )
            return cur.rowcount > 0

    # --- validators --------------------------------------------------------- #

    def add_validator(
        self, validator_id: str, operator: str, public_key_hex: str, region: str
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO validators(validator_id, operator, public_key, region, joined_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(validator_id) DO UPDATE SET active=1""",
                (validator_id, operator, public_key_hex, region, time.time()),
            )

    def list_validators(self, only_active: bool = True) -> list[sqlite3.Row]:
        with self._lock:
            q = "SELECT * FROM validators"
            if only_active:
                q += " WHERE active=1"
            q += " ORDER BY joined_at"
            return list(self._conn.execute(q))

    def deactivate_validator(self, validator_id: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE validators SET active=0 WHERE validator_id=?", (validator_id,))

    # --- reputation --------------------------------------------------------- #

    def get_reputation(self, device_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM reputation WHERE device_id=?", (device_id,)
            ).fetchone()

    def adjust_reputation(self, device_id: str, delta: float, abuse: bool, success: bool) -> float:
        with self.tx() as c:
            row = c.execute("SELECT * FROM reputation WHERE device_id=?", (device_id,)).fetchone()
            if row is None:
                score = max(0.0, min(100.0, 100.0 + delta))
                c.execute(
                    """INSERT INTO reputation(device_id, score, abuse_reports, successful_uses, last_updated)
                       VALUES(?,?,?,?,?)""",
                    (device_id, score, int(abuse), int(success), time.time()),
                )
                return score
            new_score = max(0.0, min(100.0, row["score"] + delta))
            c.execute(
                """UPDATE reputation
                     SET score=?,
                         abuse_reports=abuse_reports+?,
                         successful_uses=successful_uses+?,
                         last_updated=?
                   WHERE device_id=?""",
                (new_score, int(abuse), int(success), time.time(), device_id),
            )
            return new_score

    # --- verifications ------------------------------------------------------ #

    def record_verification(
        self, token_id: str, requester: str, valid: bool, quorum: dict
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO verifications(token_id, requester, ts, valid, quorum)
                   VALUES(?,?,?,?,?)""",
                (token_id, requester, time.time(), int(valid), json.dumps(quorum)),
            )

    def recent_verifications(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(
                "SELECT * FROM verifications ORDER BY id DESC LIMIT ?", (limit,)
            ))

    # --- premium ------------------------------------------------------------ #

    def link_premium(
        self,
        device_id: str,
        aadhaar_hash: str | None,
        upi_handle: str | None,
        digilocker_id: str | None,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO premium_links(device_id, aadhaar_hash, upi_handle, digilocker_id, linked_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(device_id) DO UPDATE SET
                     aadhaar_hash=excluded.aadhaar_hash,
                     upi_handle=excluded.upi_handle,
                     digilocker_id=excluded.digilocker_id,
                     linked_at=excluded.linked_at""",
                (device_id, aadhaar_hash, upi_handle, digilocker_id, time.time()),
            )

    def get_premium(self, device_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM premium_links WHERE device_id=?", (device_id,)
            ).fetchone()

    # --- aggregate stats ---------------------------------------------------- #

    def stats(self) -> dict[str, Any]:
        with self._lock:
            c = self._conn
            return {
                "devices": c.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
                "tokens_active": c.execute(
                    "SELECT COUNT(*) FROM tokens WHERE revoked=0 AND expires_at > ?", (time.time(),)
                ).fetchone()[0],
                "tokens_revoked": c.execute(
                    "SELECT COUNT(*) FROM tokens WHERE revoked=1"
                ).fetchone()[0],
                "validators": c.execute("SELECT COUNT(*) FROM validators WHERE active=1").fetchone()[0],
                "verifications_total": c.execute("SELECT COUNT(*) FROM verifications").fetchone()[0],
                "verifications_passed": c.execute(
                    "SELECT COUNT(*) FROM verifications WHERE valid=1"
                ).fetchone()[0],
            }
