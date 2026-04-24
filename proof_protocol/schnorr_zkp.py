"""Non-interactive zero-knowledge proofs (Schnorr / Sigma protocols).

Implements two primitives used by the PROOF Protocol:

1. ``schnorr_sign`` / ``schnorr_verify``  — proves knowledge of a discrete
   logarithm (used as the device-bound signature on a behavioral commitment).

2. ``prove_commitment_knowledge`` /
   ``verify_commitment_knowledge`` — a Sigma protocol that proves knowledge
   of ``(m, r)`` such that ``C = m·G + r·H`` *without revealing ``m`` or
   ``r``*. Made non-interactive via the Fiat–Shamir transform, this is the
   "I am human" zero-knowledge proof carried by every PROOF token.
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto_primitives import (
    G,
    H,
    N,
    Point,
    hash_to_scalar,
    point_add,
    random_scalar,
    scalar_mult,
)


# --------------------------------------------------------------------------- #
# Schnorr signature (proof of knowledge of a discrete log w.r.t. G)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SchnorrSig:
    R: Point   # commitment
    s: int     # response


def schnorr_sign(secret_key: int, message: bytes) -> SchnorrSig:
    public_key = scalar_mult(secret_key, G)
    k = random_scalar()
    R = scalar_mult(k, G)
    e = hash_to_scalar(R.to_bytes(), public_key.to_bytes(), message)
    s = (k + e * secret_key) % N
    return SchnorrSig(R=R, s=s)


def schnorr_verify(public_key: Point, message: bytes, sig: SchnorrSig) -> bool:
    if sig.R.is_infinity():
        return False
    e = hash_to_scalar(sig.R.to_bytes(), public_key.to_bytes(), message)
    lhs = scalar_mult(sig.s, G)
    rhs = point_add(sig.R, scalar_mult(e, public_key))
    return lhs == rhs


# --------------------------------------------------------------------------- #
# ZK proof of knowledge of a Pedersen-commitment opening
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CommitmentZKProof:
    """Proof that the prover knows (m, r) such that C = m·G + r·H."""

    A: Point   # commitment T = a·G + b·H
    z1: int    # response for m
    z2: int    # response for r

    def to_bytes(self) -> bytes:
        return (
            self.A.to_bytes()
            + self.z1.to_bytes(32, "big")
            + self.z2.to_bytes(32, "big")
        )


def prove_commitment_knowledge(
    message_scalar: int,
    randomness: int,
    commitment: Point,
    context: bytes = b"",
) -> CommitmentZKProof:
    """Prove knowledge of (m, r) with C = m·G + r·H (Fiat–Shamir Sigma proof)."""
    a = random_scalar()
    b = random_scalar()
    T = point_add(scalar_mult(a, G), scalar_mult(b, H))
    e = hash_to_scalar(T.to_bytes(), commitment.to_bytes(), context)
    z1 = (a + e * message_scalar) % N
    z2 = (b + e * randomness) % N
    return CommitmentZKProof(A=T, z1=z1, z2=z2)


def verify_commitment_knowledge(
    commitment: Point,
    proof: CommitmentZKProof,
    context: bytes = b"",
) -> bool:
    if proof.A.is_infinity() or commitment.is_infinity():
        return False
    e = hash_to_scalar(proof.A.to_bytes(), commitment.to_bytes(), context)
    lhs = point_add(scalar_mult(proof.z1, G), scalar_mult(proof.z2, H))
    rhs = point_add(proof.A, scalar_mult(e, commitment))
    return lhs == rhs
