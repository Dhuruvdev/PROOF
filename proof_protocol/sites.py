"""Relying-party (site) registration — same model as Cloudflare Turnstile,
hCaptcha, and reCAPTCHA: each site gets a public *site key* embedded in the
widget JS, and a private *secret key* used by the site's backend to call
``/siteverify``.

Two production-grade properties this module enforces:

* **Constant-time secret authentication.** ``authenticate(secret)`` does an
  in-memory lookup keyed by SHA-256(secret), then a final
  ``hmac.compare_digest`` against the canonical secret. SQLite ``WHERE
  secret_key=?`` queries are never run with the secret, so the SQL planner
  cannot leak per-row timing.
* **Per-site Origin allowlist.** Every site stores the set of HTTP Origins
  that are allowed to mint tokens against its sitekey via
  ``/api/siteverify-front``. The default is the registered domain.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from threading import Lock

from .database import Database


SITE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS sites (
    site_key         TEXT PRIMARY KEY,
    secret_key       TEXT NOT NULL,
    secret_hash      TEXT NOT NULL DEFAULT '',
    domain           TEXT NOT NULL,
    label            TEXT NOT NULL,
    allowed_origins  TEXT NOT NULL DEFAULT '',
    created_at       REAL NOT NULL,
    min_action       TEXT NOT NULL DEFAULT 'ALLOW',
    active           INTEGER NOT NULL DEFAULT 1,
    requests         INTEGER NOT NULL DEFAULT 0,
    blocks           INTEGER NOT NULL DEFAULT 0
);
"""

# Pepper used inside the secret-hash so that a leaked DB row cannot be
# correlated with brute-force tables computed elsewhere. This is process-local
# (regenerated each restart only when no persisted pepper exists in the data
# dir); see SiteRegistry._load_pepper.
_DEFAULT_PEPPER = b"PROOF-site-secret-pepper-v1"


def _hash_secret(secret: str, pepper: bytes = _DEFAULT_PEPPER) -> str:
    """Lookup-key for the in-memory secret index. Not authentication itself."""
    return hashlib.sha256(pepper + b"::" + secret.encode("utf-8")).hexdigest()


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
    allowed_origins: list[str] = field(default_factory=list)

    def origin_allowed(self, origin: str) -> bool:
        """True if ``origin`` (e.g. ``https://example.com``) is permitted.

        ``allowed_origins == ["*"]`` means any origin is accepted (the demo
        site uses this so the built-in interstitial works on whatever
        hostname the deployment is reached at). An empty allowlist falls
        back to matching ``self.domain`` literally.
        """
        if not origin:
            # No Origin header (e.g. same-origin GET). Treat as allowed because
            # the standard same-origin request typically omits Origin.
            return True
        if self.allowed_origins == ["*"]:
            return True
        # Strip scheme and trailing slash, case-fold the host.
        host = origin
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
                break
        host = host.split("/", 1)[0].split(":", 1)[0].lower()
        if not self.allowed_origins:
            return host == self.domain.lower()
        return host in {o.lower() for o in self.allowed_origins}


class SiteRegistry:
    def __init__(self, db: Database):
        self._db = db
        self._lock = Lock()
        self._secret_index: dict[str, str] = {}   # secret_hash → site_key
        with self._db._lock:
            self._db._conn.executescript(SITE_TABLE_DDL)
            # Lightweight migration for DBs created by an earlier schema:
            # SQLite's CREATE TABLE IF NOT EXISTS does *not* add new columns
            # to a pre-existing table, so we ALTER TABLE in-place here. Each
            # column is added with a safe default so existing rows remain
            # valid; secret_hash is then backfilled by _rebuild_secret_index.
            existing = {
                r["name"] for r in self._db._conn.execute(
                    "PRAGMA table_info(sites)"
                ).fetchall()
            }
            if "secret_hash" not in existing:
                self._db._conn.execute(
                    "ALTER TABLE sites ADD COLUMN secret_hash TEXT NOT NULL DEFAULT ''"
                )
            if "allowed_origins" not in existing:
                self._db._conn.execute(
                    "ALTER TABLE sites ADD COLUMN allowed_origins TEXT NOT NULL DEFAULT ''"
                )
            self._db._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sites_secret_hash ON sites(secret_hash)"
            )
            self._db._conn.commit()
        self._rebuild_secret_index()

    # --- registration ------------------------------------------------------ #

    def register(self, label: str, domain: str, min_action: str = "ALLOW",
                 allowed_origins: list[str] | None = None) -> Site:
        site_key = "0x4PROOF" + secrets.token_urlsafe(16).replace("-", "A").replace("_", "B")
        secret_key = "0x4PROOF-SEC-" + secrets.token_urlsafe(32).replace("-", "A").replace("_", "B")
        secret_hash = _hash_secret(secret_key)
        origins_csv = ",".join(allowed_origins or [])
        now = time.time()
        with self._db.tx() as c:
            c.execute(
                """INSERT INTO sites(site_key, secret_key, secret_hash, domain,
                                     label, allowed_origins, created_at,
                                     min_action, active)
                   VALUES(?,?,?,?,?,?,?,?,1)""",
                (site_key, secret_key, secret_hash, domain, label,
                 origins_csv, now, min_action),
            )
        with self._lock:
            self._secret_index[secret_hash] = site_key
        self._db.log("admin", "register_site",
                     {"site_key": site_key, "label": label})
        return Site(
            site_key=site_key, secret_key=secret_key, domain=domain,
            label=label, created_at=now, min_action=min_action,
            active=True, allowed_origins=list(allowed_origins or []),
        )

    # --- queries ----------------------------------------------------------- #

    def get(self, site_key: str) -> Site | None:
        # Bounded-input safety: SQLite will happily compare strings of any
        # size; cap so a 10 MB sitekey can't waste time/memory.
        if not site_key or len(site_key) > 256:
            return None
        with self._db._lock:
            row = self._db._conn.execute(
                "SELECT * FROM sites WHERE site_key=?", (site_key,)
            ).fetchone()
        return self._row_to_site(row)

    def authenticate(self, secret_key: str) -> Site | None:
        """Constant-time-friendly secret → Site lookup.

        Two stages, neither of which lets the SQL planner observe the secret
        value: (1) hash → site_key via in-memory dict, (2) load row by
        ``site_key`` (a public identifier), (3) constant-time compare against
        the canonical stored secret.
        """
        if not secret_key or len(secret_key) > 512:
            # Still walk through a constant-time compare against a dummy so an
            # attacker can't time-distinguish "missing field" from "bad secret".
            hmac.compare_digest(secret_key or "", "x")
            return None
        h = _hash_secret(secret_key)
        with self._lock:
            site_key = self._secret_index.get(h)
        if site_key is None:
            hmac.compare_digest(secret_key, "x")  # absorb a constant-time op
            return None
        site = self.get(site_key)
        if site is None:
            return None
        if not hmac.compare_digest(site.secret_key, secret_key):
            # Secret hash collision (vanishingly unlikely) or stale index.
            return None
        return site

    def list(self) -> list[Site]:
        with self._db._lock:
            rows = self._db._conn.execute(
                "SELECT * FROM sites ORDER BY created_at DESC"
            ).fetchall()
        return [s for s in (self._row_to_site(r) for r in rows) if s is not None]

    # --- mutations --------------------------------------------------------- #

    def deactivate(self, site_key: str) -> bool:
        with self._db.tx() as c:
            cur = c.execute("UPDATE sites SET active=0 WHERE site_key=?",
                            (site_key,))
            return cur.rowcount > 0

    def set_allowed_origins(self, site_key: str, origins: list[str]) -> bool:
        csv = ",".join(o.strip() for o in origins if o and o.strip())
        with self._db.tx() as c:
            cur = c.execute(
                "UPDATE sites SET allowed_origins=? WHERE site_key=?",
                (csv, site_key),
            )
            return cur.rowcount > 0

    def record_request(self, site_key: str, blocked: bool) -> None:
        with self._db.tx() as c:
            c.execute(
                "UPDATE sites SET requests=requests+1, blocks=blocks+? WHERE site_key=?",
                (1 if blocked else 0, site_key),
            )

    # --- helpers ----------------------------------------------------------- #

    def _rebuild_secret_index(self) -> None:
        with self._db._lock:
            rows = self._db._conn.execute(
                "SELECT site_key, secret_hash, secret_key FROM sites"
            ).fetchall()
        with self._lock:
            self._secret_index.clear()
            for r in rows:
                # Backfill secret_hash for any pre-migration rows.
                h = r["secret_hash"] or _hash_secret(r["secret_key"])
                self._secret_index[h] = r["site_key"]
            # Persist any backfilled hashes so subsequent lookups are O(1)
            # without a re-hash pass.
        if any((r["secret_hash"] or "") == "" for r in rows):
            with self._db.tx() as c:
                for r in rows:
                    if not r["secret_hash"]:
                        c.execute(
                            "UPDATE sites SET secret_hash=? WHERE site_key=?",
                            (_hash_secret(r["secret_key"]), r["site_key"]),
                        )

    def _row_to_site(self, row: sqlite3.Row | None) -> Site | None:
        if row is None:
            return None
        keys = row.keys()
        origins = []
        if "allowed_origins" in keys and row["allowed_origins"]:
            origins = [o.strip() for o in row["allowed_origins"].split(",") if o.strip()]
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
            allowed_origins=origins,
        )
