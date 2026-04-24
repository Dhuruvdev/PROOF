"""Pedersen commitments over secp256k1.

A Pedersen commitment ``C = m·G + r·H`` perfectly hides the message ``m``
(uniformly random ``r``) and is computationally binding under the discrete
logarithm assumption (because the discrete log of H w.r.t. G is unknown).
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto_primitives import G, H, Point, point_add, random_scalar, scalar_mult


@dataclass(frozen=True)
class Commitment:
    point: Point
    randomness: int  # opening — must stay secret

    def to_bytes(self) -> bytes:
        return self.point.to_bytes()


def commit(message_scalar: int, randomness: int | None = None) -> Commitment:
    """Commit to ``message_scalar`` (already reduced mod N)."""
    if randomness is None:
        randomness = random_scalar()
    point = point_add(scalar_mult(message_scalar, G), scalar_mult(randomness, H))
    return Commitment(point=point, randomness=randomness)


def verify_opening(commitment_point: Point, message_scalar: int, randomness: int) -> bool:
    expected = point_add(scalar_mult(message_scalar, G), scalar_mult(randomness, H))
    return expected == commitment_point
