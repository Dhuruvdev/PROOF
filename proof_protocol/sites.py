"""Relying-party (site) registration — the same model as Cloudflare
Turnstile, hCaptcha, and reCAPTCHA: each site gets a public *site key*
embedded in the widget JS, and a private *secret key* used by the site's
backend to call ``/siteverify``.
"""

from __future__ import annotations

import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .database import Database


SITE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS sites (
    site_key      TEXT PRIMARY KEY,
    secret_key    TEXT NOT NULL,
    domain        TEXT NOT NULL,
    label         TEXT NOT NULL,
    created_at    REAL NOT NULL,
    min_action    TEXT NOT NULL DEFAULT 'ALLOW',
    active        INTEGER NOT NULL DEFAULT 1,
    requests      INTEGER NOT NULL DEFAULT 0,
    blocks        INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class Site:
    site_key: str
    secret_key: str
    domain: str
    label: str
    created_at: float
    min_action: str
    active: bool
    requests: int = 0
    blocks: int = 0


class SiteRegistry:
    def __init__(self, db: Database):
        self._db = db
        with self._db._lock:
            # executescript() implicitly commits, so it must run outside tx()
            self._db._conn.executescript(SITE_TABLE_DDL)

    def register(self, label: str, domain: str, min_action: str = "ALLOW") -> Site:
        site_key = "0x4PROOF" + secrets.token_urlsafe(16).replace("-", "A").replace("_", "B")
        secret_key = "0x4PROOF-SEC-" + secrets.token_urlsafe(32).replace("-", "A").replace("_", "B")
        now = time.time()
        with self._db.tx() as c:
            c.execute(
                """INSERT INTO sites(site_key, secret_key, domain, label, created_at, min_action, active)
                   VALUES(?,?,?,?,?,?,1)""",
                (site_key, secret_key, domain, label, now, min_action),
            )
        self._db.log("admin", "register_site", {"site_key": site_key, "label": label})
        return Site(site_key=site_key, secret_key=secret_key, domain=domain, label=label,
                    created_at=now, min_action=min_action, active=True)

    def get(self, site_key: str) -> Site | None:
        with self._db._lock:
            row = self._db._conn.execute(
                "SELECT * FROM sites WHERE site_key=?", (site_key,)
            ).fetchone()
        return self._row_to_site(row)

    def authenticate(self, secret_key: str) -> Site | None:
        with self._db._lock:
            row = self._db._conn.execute(
                "SELECT * FROM sites WHERE secret_key=?", (secret_key,)
            ).fetchone()
        return self._row_to_site(row)

    def list(self) -> list[Site]:
        with self._db._lock:
            rows = self._db._conn.execute(
                "SELECT * FROM sites ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_site(r) for r in rows if r is not None]

    def deactivate(self, site_key: str) -> bool:
        with self._db.tx() as c:
            cur = c.execute("UPDATE sites SET active=0 WHERE site_key=?", (site_key,))
            return cur.rowcount > 0

    def record_request(self, site_key: str, blocked: bool) -> None:
        with self._db.tx() as c:
            c.execute(
                "UPDATE sites SET requests=requests+1, blocks=blocks+? WHERE site_key=?",
                (1 if blocked else 0, site_key),
            )

    def _row_to_site(self, row: sqlite3.Row | None) -> Site | None:
        if row is None:
            return None
        return Site(
            site_key=row["site_key"],
            secret_key=row["secret_key"],
            domain=row["domain"],
            label=row["label"],
            created_at=row["created_at"],
            min_action=row["min_action"],
            active=bool(row["active"]),
            requests=row["requests"],
            blocks=row["blocks"],
        )
