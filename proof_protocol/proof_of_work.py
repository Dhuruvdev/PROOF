"""Hashcash-style proof-of-work — the silent, non-interactive challenge.

The PROOF Network issues a random ``challenge_id`` to every visiting
client. The client must find a 64-bit integer ``nonce`` such that

    sha256(challenge_id || nonce_be8)  has at least ``difficulty`` leading
                                       zero *bits*.

This is the same primitive that powers Hashcash (1997, Adam Back) and the
Bitcoin block header — it is genuinely unforgeable, requires no shared
secret, and forces every solver to spend measurable CPU time. Difficulty
auto-adapts so that an honest browser solves it in roughly 50–250 ms,
making it invisible to humans but a meaningful tax on bot farms running
millions of attempts per minute.

Difficulty is signed by the issuer key so a client cannot lower it
unilaterally.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass


_DEFAULT_DIFFICULTY = 18      # ~262K hashes; ~50–200 ms in modern JS
MIN_DIFFICULTY = 8
MAX_DIFFICULTY = 26
CHALLENGE_TTL_SECONDS = 120


@dataclass(frozen=True)
class PowChallenge:
    challenge_id: str
    difficulty: int
    issued_at: float
    expires_at: float
    issuer_mac: str       # HMAC over (challenge_id || difficulty || expires_at)

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "difficulty": self.difficulty,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer_mac": self.issuer_mac,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PowChallenge":
        return cls(
            challenge_id=d["challenge_id"],
            difficulty=int(d["difficulty"]),
            issued_at=float(d["issued_at"]),
            expires_at=float(d["expires_at"]),
            issuer_mac=d["issuer_mac"],
        )


@dataclass(frozen=True)
class PowSolution:
    challenge_id: str
    nonce: int
    elapsed_seconds: float

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "elapsed_seconds": self.elapsed_seconds,
        }


class ProofOfWorkIssuer:
    """Issues and verifies adaptive PoW challenges."""

    def __init__(self, secret_key: bytes | None = None, base_difficulty: int = _DEFAULT_DIFFICULTY):
        self._secret = secret_key or secrets.token_bytes(32)
        self._base = max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, base_difficulty))

    def issue(self, risk_score: float = 0.0) -> PowChallenge:
        """Return a fresh challenge whose difficulty scales with ``risk_score``.

        risk_score in [0, 100]: higher → harder PoW (up to +6 bits).
        """
        bonus = int(round((risk_score / 100.0) * 6))
        difficulty = max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, self._base + bonus))
        cid = secrets.token_hex(16)
        now = time.time()
        expires = now + CHALLENGE_TTL_SECONDS
        mac = self._mac(cid, difficulty, expires)
        return PowChallenge(challenge_id=cid, difficulty=difficulty,
                            issued_at=now, expires_at=expires, issuer_mac=mac)

    def verify(self, challenge: PowChallenge, solution: PowSolution) -> tuple[bool, str]:
        if not hmac.compare_digest(
            challenge.issuer_mac,
            self._mac(challenge.challenge_id, challenge.difficulty, challenge.expires_at),
        ):
            return False, "challenge MAC invalid (forged)"
        if time.time() > challenge.expires_at:
            return False, "challenge expired"
        if challenge.challenge_id != solution.challenge_id:
            return False, "challenge / solution mismatch"
        if not _meets_difficulty(challenge.challenge_id, solution.nonce, challenge.difficulty):
            return False, f"insufficient work for difficulty {challenge.difficulty}"
        return True, "ok"

    def _mac(self, challenge_id: str, difficulty: int, expires_at: float) -> str:
        msg = f"{challenge_id}|{difficulty}|{expires_at:.6f}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()


def _meets_difficulty(challenge_id: str, nonce: int, difficulty: int) -> bool:
    h = hashlib.sha256(challenge_id.encode("utf-8") + nonce.to_bytes(8, "big")).digest()
    return _leading_zero_bits(h) >= difficulty


def _leading_zero_bits(b: bytes) -> int:
    n = 0
    for byte in b:
        if byte == 0:
            n += 8
            continue
        # bit_length tells us the position of the highest set bit
        n += 8 - byte.bit_length()
        return n
    return n


def solve(challenge: PowChallenge, max_iterations: int = 1 << 24) -> PowSolution:
    """Reference solver — used by the test harness and by the headless fallback."""
    start = time.perf_counter()
    cid_bytes = challenge.challenge_id.encode("utf-8")
    target_bits = challenge.difficulty
    for nonce in range(max_iterations):
        h = hashlib.sha256(cid_bytes + nonce.to_bytes(8, "big")).digest()
        if _leading_zero_bits(h) >= target_bits:
            elapsed = time.perf_counter() - start
            return PowSolution(challenge_id=challenge.challenge_id, nonce=nonce,
                               elapsed_seconds=elapsed)
    raise RuntimeError(f"PoW unsolved within {max_iterations} attempts")
