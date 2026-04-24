"""PROOF Validator Network — open, NPCI-style consensus layer.

Each validator is an independent verifier. A token is "valid" only when
a configurable quorum (default 2/3) of currently-active validators
independently agree:

  1. The Schnorr signature over the token payload is valid w.r.t. the
     enrolled device public key.
  2. The embedded zero-knowledge proof of commitment knowledge verifies
     against the device's enrolled commitment.
  3. The token has not expired and has not been revoked.

Validators are themselves keypairs; their attestations are Schnorr-signed
so a downstream relying party can audit the quorum end-to-end.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Iterable

from . import crypto_primitives as cp
from .database import Database
from .schnorr_zkp import (
    CommitmentZKProof,
    SchnorrSig,
    schnorr_sign,
    schnorr_verify,
    verify_commitment_knowledge,
)


@dataclass
class ValidatorAttestation:
    validator_id: str
    decision: bool
    reason: str
    timestamp: float
    signature: SchnorrSig

    def to_dict(self) -> dict:
        return {
            "validator_id": self.validator_id,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": {
                "R": self.signature.R.to_bytes().hex(),
                "s": hex(self.signature.s),
            },
        }


@dataclass
class QuorumResult:
    valid: bool
    yes: int
    no: int
    total: int
    threshold: int
    attestations: list[ValidatorAttestation]
    failure_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "yes": self.yes,
            "no": self.no,
            "total": self.total,
            "threshold": self.threshold,
            "failure_reason": self.failure_reason,
            "attestations": [a.to_dict() for a in self.attestations],
        }


class Validator:
    """A single PROOF Network validator node."""

    def __init__(self, validator_id: str, operator: str, region: str, db: Database):
        self.validator_id = validator_id
        self.operator = operator
        self.region = region
        self._db = db
        self._sk, self._pk = cp.keypair()
        db.add_validator(
            validator_id=self.validator_id,
            operator=operator,
            public_key_hex=self._pk.to_bytes().hex(),
            region=region,
        )
        db.log("validator", "join", {"validator_id": validator_id, "operator": operator, "region": region})

    @property
    def public_key(self) -> cp.Point:
        return self._pk

    def attest(
        self,
        token_id: str,
        device_pk: cp.Point,
        commitment: cp.Point,
        zk_proof: CommitmentZKProof,
        device_signature: SchnorrSig,
        signed_payload: bytes,
        expires_at: float,
        revoked: bool,
        context: bytes,
    ) -> ValidatorAttestation:
        decision = True
        reason = "ok"

        if revoked:
            decision, reason = False, "token revoked"
        elif time.time() > expires_at:
            decision, reason = False, "token expired"
        elif not schnorr_verify(device_pk, signed_payload, device_signature):
            decision, reason = False, "device signature invalid"
        elif not verify_commitment_knowledge(commitment, zk_proof, context=context):
            decision, reason = False, "zk proof of humanity invalid"

        ts = time.time()
        sig_msg = (
            self.validator_id.encode()
            + token_id.encode()
            + (b"Y" if decision else b"N")
            + reason.encode()
            + str(ts).encode()
        )
        sig = schnorr_sign(self._sk, sig_msg)
        return ValidatorAttestation(
            validator_id=self.validator_id,
            decision=decision,
            reason=reason,
            timestamp=ts,
            signature=sig,
        )


class ValidatorNetwork:
    """Coordinator over a pool of independent validators."""

    def __init__(self, db: Database, quorum_ratio: float = 2 / 3):
        self._db = db
        self._validators: list[Validator] = []
        self._quorum_ratio = quorum_ratio

    def add_validator(self, operator: str, region: str) -> Validator:
        vid = f"v-{len(self._validators) + 1:03d}-{operator.lower().replace(' ', '-')}"
        v = Validator(validator_id=vid, operator=operator, region=region, db=self._db)
        self._validators.append(v)
        return v

    def remove_validator(self, validator_id: str) -> bool:
        before = len(self._validators)
        self._validators = [v for v in self._validators if v.validator_id != validator_id]
        if len(self._validators) < before:
            self._db.deactivate_validator(validator_id)
            self._db.log("validator", "leave", {"validator_id": validator_id})
            return True
        return False

    def active_validators(self) -> list[Validator]:
        return list(self._validators)

    def threshold(self) -> int:
        n = len(self._validators)
        if n == 0:
            return 0
        # Ceil(n * ratio), at least 1
        return max(1, -(-int(n * self._quorum_ratio * 1000) // 1000))

    def verify_token(
        self,
        token_id: str,
        device_pk: cp.Point,
        commitment: cp.Point,
        zk_proof: CommitmentZKProof,
        device_signature: SchnorrSig,
        signed_payload: bytes,
        expires_at: float,
        revoked: bool,
        context: bytes,
        requester: str,
    ) -> QuorumResult:
        if not self._validators:
            qr = QuorumResult(
                valid=False, yes=0, no=0, total=0, threshold=0,
                attestations=[], failure_reason="no active validators",
            )
            self._db.record_verification(token_id, requester, qr.valid, qr.to_dict())
            return qr

        attestations: list[ValidatorAttestation] = []
        for v in self._validators:
            attestations.append(
                v.attest(
                    token_id=token_id,
                    device_pk=device_pk,
                    commitment=commitment,
                    zk_proof=zk_proof,
                    device_signature=device_signature,
                    signed_payload=signed_payload,
                    expires_at=expires_at,
                    revoked=revoked,
                    context=context,
                )
            )

        yes = sum(1 for a in attestations if a.decision)
        no = len(attestations) - yes
        threshold = self.threshold()
        valid = yes >= threshold

        # Surface the most common "no" reason, if any, for diagnostics.
        failure_reason: str | None = None
        if not valid:
            reasons: dict[str, int] = {}
            for a in attestations:
                if not a.decision:
                    reasons[a.reason] = reasons.get(a.reason, 0) + 1
            if reasons:
                failure_reason = max(reasons.items(), key=lambda kv: kv[1])[0]
            else:
                failure_reason = f"only {yes}/{threshold} validators agreed"

        qr = QuorumResult(
            valid=valid,
            yes=yes,
            no=no,
            total=len(attestations),
            threshold=threshold,
            attestations=attestations,
            failure_reason=failure_reason,
        )
        self._db.record_verification(token_id, requester, qr.valid, qr.to_dict())
        return qr

    @staticmethod
    def verify_attestation_chain(
        attestations: Iterable[ValidatorAttestation],
        validator_pubkeys: dict[str, cp.Point],
        token_id: str,
    ) -> bool:
        """Independently verify each validator's signature over its decision."""
        for a in attestations:
            pk = validator_pubkeys.get(a.validator_id)
            if pk is None:
                return False
            sig_msg = (
                a.validator_id.encode()
                + token_id.encode()
                + (b"Y" if a.decision else b"N")
                + a.reason.encode()
                + str(a.timestamp).encode()
            )
            if not schnorr_verify(pk, sig_msg, a.signature):
                return False
        return True


def serialize_quorum_compact(qr: QuorumResult) -> str:
    return json.dumps(
        {
            "valid": qr.valid,
            "yes": qr.yes,
            "no": qr.no,
            "total": qr.total,
            "threshold": qr.threshold,
            "failure_reason": qr.failure_reason,
            "attestations": [
                {"validator_id": a.validator_id, "decision": a.decision, "reason": a.reason}
                for a in qr.attestations
            ],
        },
        indent=2,
    )
