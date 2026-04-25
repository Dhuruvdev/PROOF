"""Hashcash-style proof-of-work — silent, non-interactive challenge.

The PROOF Network issues a random ``challenge_id`` to every visiting
client. The client must find a 64-bit integer ``nonce`` such that

    sha256(challenge_id || sitekey || telemetry_hash || nonce_be8)
        has at least ``difficulty`` leading zero *bits*.

Three things are bound into the hashed input — not just the random
challenge id — so that a precomputed solution can never be reused:

* ``sitekey``        — solution from one site is invalid on another.
* ``telemetry_hash`` — solution computed against telemetry T1 cannot be
                       attached to telemetry T2 at submission time.

This is the same primitive that powers Hashcash (Adam Back, 1997) and
Bitcoin block headers — it is genuinely unforgeable, requires no shared
secret, and forces every solver to spend measurable CPU time. Difficulty
auto-adapts so an honest browser solves it in roughly 50–250 ms, making
it invisible to humans but a meaningful tax on bot farms running millions
of attempts per minute. The challenge MAC is signed with the issuer key
so a client cannot forge or downgrade a challenge.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass


# 14 bits ≈ 16K SHA-256 hashes ≈ 50–250 ms in real V8/SpiderMonkey on
# a mid-range mobile, ≈ 5–10 ms on desktop. Cheap enough to be invisible
# to a human, expensive enough that one CPU core caps at ~5 verifications
# per second — a meaningful tax on a bot farm.
_DEFAULT_DIFFICULTY = 14
MIN_DIFFICULTY = 10
MAX_DIFFICULTY = 26
CHALLENGE_TTL_SECONDS = 120

# Hex-string telemetry_hash length (SHA-256). Empty hash is forbidden — every
# legitimate submission has telemetry, even if mostly zeros.
_TELEMETRY_HASH_HEX_LEN = 64


@dataclass(frozen=True)
class PowChallenge:
    challenge_id: str
    difficulty: int
    issued_at: float
    expires_at: float
    sitekey: str          # bound at issue time, replayed verbatim at verify
    issuer_mac: str       # HMAC over canonical (cid || diff || expires_us || sitekey)

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "difficulty": self.difficulty,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "sitekey": self.sitekey,
            "issuer_mac": self.issuer_mac,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PowChallenge":
        return cls(
            challenge_id=str(d["challenge_id"]),
            difficulty=int(d["difficulty"]),
            issued_at=float(d["issued_at"]),
            expires_at=float(d["expires_at"]),
            sitekey=str(d["sitekey"]),
            issuer_mac=str(d["issuer_mac"]),
        )


@dataclass(frozen=True)
class PowSolution:
    challenge_id: str
    nonce: int
    elapsed_seconds: float
    telemetry_hash: str   # hex SHA-256 of the verbatim telemetry JSON

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "elapsed_seconds": self.elapsed_seconds,
            "telemetry_hash": self.telemetry_hash,
        }


class ProofOfWorkIssuer:
    """Issues and verifies adaptive PoW challenges bound to (sitekey)."""

    def __init__(self, secret_key: bytes | None = None,
                 base_difficulty: int = _DEFAULT_DIFFICULTY):
        self._secret = secret_key or secrets.token_bytes(32)
        self._base = max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, base_difficulty))

    # --- issuance ---------------------------------------------------------- #

    def issue(self, sitekey: str, risk_score: float = 0.0) -> PowChallenge:
        """Return a fresh challenge whose difficulty scales with ``risk_score``.

        risk_score in [0, 100]: higher → harder PoW (up to +6 bits).
        """
        if not sitekey or not isinstance(sitekey, str) or len(sitekey) > 256:
            raise ValueError("sitekey is required and must be ≤256 chars")
        bonus = int(round((max(0.0, min(100.0, risk_score)) / 100.0) * 6))
        difficulty = max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, self._base + bonus))
        cid = secrets.token_hex(16)
        now = time.time()
        expires = now + CHALLENGE_TTL_SECONDS
        mac = self._mac(cid, difficulty, expires, sitekey)
        return PowChallenge(challenge_id=cid, difficulty=difficulty,
                            issued_at=now, expires_at=expires,
                            sitekey=sitekey, issuer_mac=mac)

    # --- verification ------------------------------------------------------ #

    def verify(
        self,
        challenge: PowChallenge,
        solution: PowSolution,
        sitekey: str,
        telemetry_hash: str,
    ) -> tuple[bool, str]:
        # 1. Challenge MAC integrity. Includes sitekey, so cross-site replay
        #    fails here.
        if not hmac.compare_digest(
            challenge.issuer_mac,
            self._mac(challenge.challenge_id, challenge.difficulty,
                      challenge.expires_at, challenge.sitekey),
        ):
            return False, "challenge MAC invalid (forged or tampered)"
        # 2. The submission's sitekey must equal what we signed.
        if not hmac.compare_digest(challenge.sitekey, sitekey or ""):
            return False, "sitekey mismatch (challenge bound to a different site)"
        # 3. Expiry.
        if time.time() > challenge.expires_at:
            return False, "challenge expired"
        # 4. The solution must reference the same challenge_id we issued.
        if not hmac.compare_digest(challenge.challenge_id, solution.challenge_id):
            return False, "challenge / solution id mismatch"
        # 5. The solution must reference the telemetry the client claimed it
        #    used. The caller is expected to recompute telemetry_hash from the
        #    verbatim telemetry payload.
        if not isinstance(telemetry_hash, str) or len(telemetry_hash) != _TELEMETRY_HASH_HEX_LEN:
            return False, "telemetry_hash missing or wrong length"
        if not hmac.compare_digest(solution.telemetry_hash, telemetry_hash):
            return False, "telemetry was modified after the proof-of-work was solved"
        # 6. Honest work check on the bound input.
        if not _meets_difficulty(challenge.challenge_id, sitekey, telemetry_hash,
                                 solution.nonce, challenge.difficulty):
            return False, f"insufficient work for difficulty {challenge.difficulty}"
        return True, "ok"

    # --- canonical MAC ----------------------------------------------------- #

    def _mac(self, challenge_id: str, difficulty: int, expires_at: float,
             sitekey: str) -> str:
        # Use integer microseconds — float repr is platform-dependent and would
        # otherwise silently invalidate every outstanding challenge across a
        # Python upgrade.
        expires_us = int(round(expires_at * 1_000_000))
        msg = b"|".join([
            b"proof.pow.v2",
            challenge_id.encode("ascii"),
            str(int(difficulty)).encode("ascii"),
            str(expires_us).encode("ascii"),
            sitekey.encode("utf-8"),
        ])
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Hash binding + difficulty math
# --------------------------------------------------------------------------- #


def pow_hash_bytes(challenge_id: str, sitekey: str, telemetry_hash: str,
                   nonce: int) -> bytes:
    """The exact 256-bit digest the client must drive below the target."""
    return hashlib.sha256(
        challenge_id.encode("utf-8")
        + b"|"
        + sitekey.encode("utf-8")
        + b"|"
        + telemetry_hash.encode("ascii")
        + b"|"
        + nonce.to_bytes(8, "big")
    ).digest()


def _meets_difficulty(challenge_id: str, sitekey: str, telemetry_hash: str,
                      nonce: int, difficulty: int) -> bool:
    return _leading_zero_bits(
        pow_hash_bytes(challenge_id, sitekey, telemetry_hash, nonce)
    ) >= difficulty


def _leading_zero_bits(b: bytes) -> int:
    n = 0
    for byte in b:
        if byte == 0:
            n += 8
            continue
        n += 8 - byte.bit_length()
        return n
    return n


def solve(challenge: PowChallenge, sitekey: str, telemetry_hash: str,
          max_iterations: int = 1 << 24) -> PowSolution:
    """Reference solver — used by the test harness and the headless fallback.

    The test/CLI client passes the same ``sitekey`` and ``telemetry_hash`` it
    will submit, so the produced solution is bound to that exact context.
    """
    if not isinstance(telemetry_hash, str) or len(telemetry_hash) != _TELEMETRY_HASH_HEX_LEN:
        raise ValueError("telemetry_hash must be a 64-hex SHA-256 digest")
    start = time.perf_counter()
    target_bits = challenge.difficulty
    for nonce in range(max_iterations):
        if _leading_zero_bits(
            pow_hash_bytes(challenge.challenge_id, sitekey, telemetry_hash, nonce)
        ) >= target_bits:
            elapsed = time.perf_counter() - start
            return PowSolution(
                challenge_id=challenge.challenge_id,
                nonce=nonce,
                elapsed_seconds=elapsed,
                telemetry_hash=telemetry_hash,
            )
    raise RuntimeError(f"PoW unsolved within {max_iterations} attempts")
