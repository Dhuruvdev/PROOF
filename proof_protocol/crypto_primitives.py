"""Cryptographic primitives for the PROOF Protocol.

Uses the secp256k1 elliptic curve for all group operations. All randomness
is sourced from the operating system CSPRNG via ``secrets``.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple


# secp256k1 domain parameters (SEC 2, v2)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class Point:
    """An affine point on secp256k1, or the point at infinity (x=y=None)."""

    x: int | None
    y: int | None

    @classmethod
    def infinity(cls) -> "Point":
        return cls(None, None)

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def to_bytes(self) -> bytes:
        """Compressed SEC1 encoding (33 bytes)."""
        if self.is_infinity():
            return b"\x00"
        prefix = b"\x02" if self.y % 2 == 0 else b"\x03"
        return prefix + self.x.to_bytes(32, "big")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Point":
        if data == b"\x00":
            return cls.infinity()
        if len(data) != 33 or data[0] not in (2, 3):
            raise ValueError("Invalid compressed point")
        x = int.from_bytes(data[1:], "big")
        y_sq = (pow(x, 3, P) + A * x + B) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if (y % 2) != (data[0] - 2):
            y = P - y
        if (y * y - y_sq) % P != 0:
            raise ValueError("Point not on curve")
        return cls(x, y)


G = Point(GX, GY)


def _inv_mod(a: int, m: int) -> int:
    return pow(a % m, -1, m)


def point_add(p1: Point, p2: Point) -> Point:
    if p1.is_infinity():
        return p2
    if p2.is_infinity():
        return p1
    if p1.x == p2.x and (p1.y + p2.y) % P == 0:
        return Point.infinity()
    if p1.x == p2.x and p1.y == p2.y:
        # Doubling
        s = (3 * p1.x * p1.x + A) * _inv_mod(2 * p1.y, P) % P
    else:
        s = (p2.y - p1.y) * _inv_mod(p2.x - p1.x, P) % P
    x3 = (s * s - p1.x - p2.x) % P
    y3 = (s * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def scalar_mult(k: int, point: Point) -> Point:
    """Constant-iteration double-and-add. ``k`` is reduced mod N."""
    k = k % N
    if k == 0 or point.is_infinity():
        return Point.infinity()
    result = Point.infinity()
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def random_scalar() -> int:
    """Sample a uniformly random non-zero scalar in [1, N-1]."""
    while True:
        k = secrets.randbelow(N)
        if k != 0:
            return k


def hash_to_scalar(*chunks: bytes) -> int:
    """Hash arbitrary byte chunks to a scalar mod N (Fiat–Shamir transform)."""
    h = hashlib.sha256()
    for c in chunks:
        h.update(len(c).to_bytes(4, "big"))
        h.update(c)
    return int.from_bytes(h.digest(), "big") % N


def hash_to_point(label: bytes) -> Point:
    """Deterministic, nothing-up-my-sleeve hash-to-curve via try-and-increment."""
    counter = 0
    while True:
        digest = hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(digest, "big") % P
        y_sq = (pow(x, 3, P) + A * x + B) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if (y * y) % P == y_sq:
            return Point(x, y)
        counter += 1


# Independent generator H for Pedersen commitments. Derived from a fixed
# label so that the discrete log of H w.r.t. G is unknown — required for
# the binding property of Pedersen commitments.
H = hash_to_point(b"PROOF-Protocol-v1-Pedersen-H")


def keypair() -> Tuple[int, Point]:
    """Generate a fresh (secret_key, public_key) pair."""
    sk = random_scalar()
    pk = scalar_mult(sk, G)
    return sk, pk


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
