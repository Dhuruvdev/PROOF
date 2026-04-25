"""End-to-end PROOF Protocol orchestration.

Glues together: behavioral capture, the secure enclave, Pedersen
commitments, the ZK proof of humanity, the validator network, the trust
tier policy, and the persistent database.

This is the single API surface a relying party (or the Streamlit UI)
needs.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from . import crypto_primitives as cp
from .behavioral_dna import (
    BehavioralVector,
    cosine_distance,
    extract_features,
    matches,
    MATCH_THRESHOLD,
)
from .database import Database
from .pedersen import Commitment, commit, verify_opening
from .proof_of_work import PowChallenge, PowSolution, ProofOfWorkIssuer
from .replay_protection import ReplayGuard
from .risk_engine import Action, RiskDecision, evaluate as risk_evaluate
from .schnorr_zkp import (
    CommitmentZKProof,
    SchnorrSig,
    prove_commitment_knowledge,
    schnorr_verify,
)
from .secure_enclave import SecureEnclave, derive_device_id
from .sites import Site, SiteRegistry
from .telemetry import TelemetrySummary
from .trust_tiers import POLICIES, Tier, TierPolicy, can_issue, policy_for
from .validator_network import QuorumResult, ValidatorNetwork


# --------------------------------------------------------------------------- #
# Public datatypes
# --------------------------------------------------------------------------- #


@dataclass
class EnrollmentResult:
    device_id: str
    public_key_hex: str
    commitment_hex: str


@dataclass
class ProofToken:
    token_id: str
    device_id: str
    tier: Tier
    issued_at: float
    expires_at: float
    commitment_hex: str
    zk_proof: CommitmentZKProof
    device_signature: SchnorrSig
    nonce: bytes        # freshness — included in the signed payload
    context: bytes      # domain separator (bound to relying-party challenge)

    # ---- canonical serialisation --------------------------------------------

    def signed_payload(self) -> bytes:
        return (
            self.token_id.encode()
            + self.device_id.encode()
            + self.tier.value.encode()
            + str(self.issued_at).encode()
            + str(self.expires_at).encode()
            + bytes.fromhex(self.commitment_hex)
            + self.zk_proof.to_bytes()
            + self.nonce
            + self.context
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "token_id": self.token_id,
                "device_id": self.device_id,
                "tier": self.tier.value,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
                "commitment_hex": self.commitment_hex,
                "zk_proof": {
                    "A": self.zk_proof.A.to_bytes().hex(),
                    "z1": hex(self.zk_proof.z1),
                    "z2": hex(self.zk_proof.z2),
                },
                "device_signature": {
                    "R": self.device_signature.R.to_bytes().hex(),
                    "s": hex(self.device_signature.s),
                },
                "nonce": self.nonce.hex(),
                "context": self.context.hex(),
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, blob: str) -> "ProofToken":
        d = json.loads(blob)
        zk = CommitmentZKProof(
            A=cp.Point.from_bytes(bytes.fromhex(d["zk_proof"]["A"])),
            z1=int(d["zk_proof"]["z1"], 16),
            z2=int(d["zk_proof"]["z2"], 16),
        )
        sig = SchnorrSig(
            R=cp.Point.from_bytes(bytes.fromhex(d["device_signature"]["R"])),
            s=int(d["device_signature"]["s"], 16),
        )
        return cls(
            token_id=d["token_id"],
            device_id=d["device_id"],
            tier=Tier(d["tier"]),
            issued_at=float(d["issued_at"]),
            expires_at=float(d["expires_at"]),
            commitment_hex=d["commitment_hex"],
            zk_proof=zk,
            device_signature=sig,
            nonce=bytes.fromhex(d["nonce"]),
            context=bytes.fromhex(d["context"]),
        )


# --------------------------------------------------------------------------- #
# Protocol controller
# --------------------------------------------------------------------------- #


ENCLAVE_BLOB_NAME = "behavioral_commitment"
FEATURE_BLOB_NAME = "behavioral_features"


class ProofProtocol:
    """High-level facade. One instance per running PROOF deployment."""

    def __init__(self, data_dir: str | Path):
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        self._dir = data_dir
        self.db = Database(data_dir / "proof.sqlite")
        self.network = ValidatorNetwork(self.db)
        self.sites = SiteRegistry(self.db)
        self.pow = ProofOfWorkIssuer()
        self.replay = ReplayGuard(self.db)
        self._enclaves: dict[str, SecureEnclave] = {}
        # In-memory short-lived response tokens (response → verdict).
        # In production this would be Redis with a ~5 minute TTL. Bounded LRU
        # so a sustained flood of successful verifications cannot exhaust
        # memory; the oldest entries are evicted first.
        self._response_tokens: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self._response_tokens_lock = Lock()
        self._response_token_evictions = 0
        # Process-local pepper for fingerprint hashing in audit logs. Privacy:
        # the audit log records SHA-256(pepper||fingerprint)[:16] instead of
        # the raw browser fingerprint, so a leaked log row cannot be
        # correlated against a raw fingerprint table.
        self._fp_log_pepper = secrets.token_bytes(32)

    _RT_MAX = 4096

    def _store_response_token(self, token: str, payload: dict[str, Any]) -> None:
        with self._response_tokens_lock:
            self._response_tokens[token] = payload
            self._response_tokens.move_to_end(token)
            while len(self._response_tokens) > self._RT_MAX:
                self._response_tokens.popitem(last=False)
                self._response_token_evictions += 1

    def _hash_fp_for_log(self, fingerprint: str) -> str:
        return hashlib.sha256(
            self._fp_log_pepper + b"::" + fingerprint.encode("utf-8")
        ).hexdigest()[:16]

    # --- enclave management ------------------------------------------------- #

    def enclave_for(self, device_id: str, passphrase: str) -> SecureEnclave:
        key = f"{device_id}:{passphrase}"
        if key not in self._enclaves:
            self._enclaves[key] = SecureEnclave(
                device_id=device_id,
                passphrase=passphrase,
                storage_dir=self._dir / "enclaves",
            )
        return self._enclaves[key]

    # --- enrollment --------------------------------------------------------- #

    def enroll_device(
        self,
        machine_signals: dict[str, Any],
        passphrase: str,
        raw_events: list[dict],
    ) -> tuple[EnrollmentResult, BehavioralVector]:
        """Run a one-time enrollment for a new device-human pair."""
        device_id = derive_device_id(machine_signals)
        enclave = self.enclave_for(device_id, passphrase)

        bv = extract_features(raw_events)
        message_scalar = int.from_bytes(bv.fingerprint, "big") % cp.N
        commitment = commit(message_scalar)

        # Seal the opening (message + randomness) inside the enclave so it can
        # later prove knowledge of the commitment without ever exposing them.
        enclave.store_named(
            ENCLAVE_BLOB_NAME,
            json.dumps(
                {
                    "message_scalar_hex": hex(message_scalar),
                    "randomness_hex": hex(commitment.randomness),
                    "commitment_hex": commitment.point.to_bytes().hex(),
                }
            ).encode("utf-8"),
        )
        # Also seal the raw feature vector for re-enrollment / matching.
        enclave.store_named(
            FEATURE_BLOB_NAME,
            json.dumps({"features": list(bv.features), "fingerprint": bv.fingerprint.hex()}).encode("utf-8"),
        )

        public_key_hex = enclave.device_public_key.to_bytes().hex()
        commitment_hex = commitment.point.to_bytes().hex()
        self.db.upsert_device(device_id, public_key_hex, commitment_hex)
        self.db.log("device", "enroll", {"device_id": device_id})

        return (
            EnrollmentResult(
                device_id=device_id,
                public_key_hex=public_key_hex,
                commitment_hex=commitment_hex,
            ),
            bv,
        )

    # --- proof issuance ----------------------------------------------------- #

    def issue_token(
        self,
        device_id: str,
        passphrase: str,
        raw_events: list[dict],
        tier: Tier,
        relying_party_challenge: bytes,
    ) -> tuple[ProofToken, BehavioralVector, float]:
        """Generate a new PROOF token for ``tier``, given a fresh capture.

        Returns the token, the live behavioral vector, and the cosine
        distance to the enrolled vector.

        Raises ``PermissionError`` for tier/eligibility failures and
        ``ValueError`` if the live capture doesn't match the enrolled one.
        """
        device_row = self.db.get_device(device_id)
        if device_row is None:
            raise LookupError("Device not enrolled")

        enclave = self.enclave_for(device_id, passphrase)

        # 1. Re-capture & match against the sealed reference vector.
        live = extract_features(raw_events)
        sealed_features = json.loads(enclave.load_named(FEATURE_BLOB_NAME).decode("utf-8"))
        reference = BehavioralVector(
            features=tuple(sealed_features["features"]),
            fingerprint=bytes.fromhex(sealed_features["fingerprint"]),
        )
        ok, distance = matches(reference, live)
        if not ok:
            raise ValueError(
                f"Live behavioral capture did not match enrolled profile "
                f"(cosine distance {distance:.3f} > threshold {MATCH_THRESHOLD:.2f})."
            )

        # 2. Eligibility check against tier policy.
        rep_row = self.db.get_reputation(device_id)
        rep_score = float(rep_row["score"]) if rep_row else 100.0
        identity_linked = self.db.get_premium(device_id) is not None
        eligible, reason = can_issue(tier, rep_score, identity_linked)
        if not eligible:
            raise PermissionError(reason)

        # 3. Generate the ZK proof of commitment knowledge using the *sealed*
        #    opening — never the live capture's raw values.
        sealed_commit = json.loads(enclave.load_named(ENCLAVE_BLOB_NAME).decode("utf-8"))
        message_scalar = int(sealed_commit["message_scalar_hex"], 16)
        randomness = int(sealed_commit["randomness_hex"], 16)
        commitment_point = cp.Point.from_bytes(bytes.fromhex(sealed_commit["commitment_hex"]))

        # Sanity check — should always hold unless storage was tampered with.
        if not verify_opening(commitment_point, message_scalar, randomness):
            raise RuntimeError("Sealed commitment opening is corrupted")

        nonce = secrets.token_bytes(16)
        context = cp.sha256(relying_party_challenge + nonce + tier.value.encode())

        zk = prove_commitment_knowledge(
            message_scalar=message_scalar,
            randomness=randomness,
            commitment=commitment_point,
            context=context,
        )

        # 4. Build the token, then sign the canonical payload with the
        #    enclave-resident device key.
        policy: TierPolicy = policy_for(tier)
        issued_at = time.time()
        expires_at = issued_at + policy.token_lifetime_seconds
        token_id = f"prf-{secrets.token_hex(8)}"

        token = ProofToken(
            token_id=token_id,
            device_id=device_id,
            tier=tier,
            issued_at=issued_at,
            expires_at=expires_at,
            commitment_hex=commitment_point.to_bytes().hex(),
            zk_proof=zk,
            device_signature=SchnorrSig(R=cp.Point.infinity(), s=0),  # placeholder
            nonce=nonce,
            context=context,
        )
        # Sign payload that excludes the (still-empty) signature.
        sig = enclave.sign(token.signed_payload())
        token.device_signature = sig

        self.db.insert_token(
            token_id=token_id,
            device_id=device_id,
            tier=tier.value,
            issued_at=issued_at,
            expires_at=expires_at,
            proof_blob=token.to_json(),
        )
        self.db.adjust_reputation(device_id, delta=+1.0, abuse=False, success=True)
        self.db.log("device", "issue_token", {"device_id": device_id, "tier": tier.value, "token_id": token_id})
        return token, live, distance

    # --- verification ------------------------------------------------------- #

    def verify_token(self, token: ProofToken, requester: str) -> QuorumResult:
        device_row = self.db.get_device(token.device_id)
        if device_row is None:
            qr = QuorumResult(valid=False, yes=0, no=0, total=0, threshold=0,
                              attestations=[], failure_reason="unknown device")
            self.db.record_verification(token.token_id, requester, False, qr.to_dict())
            return qr

        device_pk = cp.Point.from_bytes(bytes.fromhex(device_row["public_key"]))
        # Cross-check: the commitment in the token MUST match the enrolled
        # commitment for this device. Otherwise the prover is trying to use a
        # fresh commitment that isn't bound to this device's identity.
        commitment_point = cp.Point.from_bytes(bytes.fromhex(token.commitment_hex))
        enrolled_commitment = cp.Point.from_bytes(bytes.fromhex(device_row["commitment"]))
        if commitment_point != enrolled_commitment:
            qr = QuorumResult(valid=False, yes=0, no=0, total=0, threshold=0,
                              attestations=[], failure_reason="commitment mismatch")
            self.db.record_verification(token.token_id, requester, False, qr.to_dict())
            return qr

        token_row = self.db.get_token(token.token_id)
        revoked = bool(token_row and token_row["revoked"])

        qr = self.network.verify_token(
            token_id=token.token_id,
            device_pk=device_pk,
            commitment=commitment_point,
            zk_proof=token.zk_proof,
            device_signature=token.device_signature,
            signed_payload=token.signed_payload(),
            expires_at=token.expires_at,
            revoked=revoked,
            context=token.context,
            requester=requester,
        )
        if qr.valid:
            self.db.adjust_reputation(token.device_id, delta=+0.1, abuse=False, success=True)
        else:
            # Don't punish the device for an expired or revoked token (those
            # are administrative states, not abuse).
            if qr.failure_reason in {"device signature invalid", "zk proof of humanity invalid"}:
                self.db.adjust_reputation(token.device_id, delta=-5.0, abuse=True, success=False)
        return qr

    # --- revocation --------------------------------------------------------- #

    def revoke_token(self, token_id: str, reason: str) -> bool:
        ok = self.db.revoke_token(token_id, reason)
        if ok:
            self.db.log("admin", "revoke_token", {"token_id": token_id, "reason": reason})
        return ok

    # --- premium link ------------------------------------------------------- #

    def link_premium_identity(
        self,
        device_id: str,
        aadhaar: str | None,
        upi_handle: str | None,
        digilocker_id: str | None,
    ) -> None:
        if self.db.get_device(device_id) is None:
            raise LookupError("Device not enrolled")
        # Aadhaar is hashed with a per-system pepper before storage — the raw
        # Aadhaar number never lands in the database.
        aadhaar_hash = (
            cp.sha256(b"PROOF-aadhaar-pepper-v1::" + aadhaar.strip().encode("utf-8")).hex()
            if aadhaar else None
        )
        self.db.link_premium(device_id, aadhaar_hash, upi_handle, digilocker_id)
        self.db.log("device", "link_premium", {"device_id": device_id})

    # --- public-API path: evaluate a visiting browser ---------------------- #

    def evaluate_visitor(
        self,
        site_key: str,
        challenge: PowChallenge,
        solution: PowSolution,
        telemetry: TelemetrySummary,
        telemetry_hash: str,
        requester: str,
    ) -> dict[str, Any]:
        """End-to-end /siteverify-front: PoW + replay + telemetry → decision.

        ``telemetry_hash`` is the SHA-256 of the verbatim telemetry JSON the
        client posted; it is used to verify the proof-of-work was solved
        against the same telemetry the client is now submitting.
        """
        site = self.sites.get(site_key)
        if not site or not site.active:
            return {
                "success": False, "action": "BLOCK", "score": 100.0,
                "reasons": ["invalid sitekey"], "response_token": "",
            }

        replay_seen = self.replay.seen_or_record(challenge.challenge_id)

        ok_pow, pow_reason = self.pow.verify(
            challenge, solution, sitekey=site_key, telemetry_hash=telemetry_hash,
        )
        if not ok_pow:
            telemetry.risk_flags.append(f"PoW: {pow_reason}")

        # Reputation lookup by browser fingerprint (independent of any
        # device-bound enrollment — see device_id below for premium flows).
        rep_row = self.db.get_reputation(telemetry.fingerprint)
        rep_score = float(rep_row["score"]) if rep_row else 100.0

        try:
            min_action = Action(site.min_action)
        except ValueError:
            min_action = Action.ALLOW

        decision: RiskDecision = risk_evaluate(
            telemetry=telemetry,
            pow_solved=ok_pow,
            pow_elapsed_ms=solution.elapsed_seconds * 1000.0,
            behavioral_distance=None,
            reputation_score=rep_score,
            replay_seen_before=replay_seen,
            relying_party_min_action=min_action,
            pow_difficulty_bits=int(challenge.difficulty),
        )

        success = decision.action in (Action.ALLOW, Action.ALLOW_WITH_INTERACTION)
        self.sites.record_request(site.site_key, blocked=not success)
        # Maintain a fingerprint-keyed reputation that drifts with verdicts.
        self.db.adjust_reputation(
            telemetry.fingerprint,
            delta=(+0.5 if success else -3.0),
            abuse=(decision.action == Action.BLOCK),
            success=success,
        )
        # Audit log records a salted hash of the fingerprint, never the raw
        # value, so a leaked log row can't be correlated with another DB.
        self.db.log("api", "siteverify_front", {
            "site": site.site_key,
            "fp_hash": self._hash_fp_for_log(telemetry.fingerprint),
            "action": decision.action.value,
            "score": round(decision.score, 2),
        })

        response_token = "RT_" + secrets.token_urlsafe(24).replace("-", "A").replace("_", "B")
        verdict = {
            "success": success,
            "action": decision.action.value,
            "score": decision.score,
            "reasons": decision.reasons,
            "fingerprint": telemetry.fingerprint,
            "ts": time.time(),
            "site_key": site.site_key,
            "components": decision.components,
        }
        # Store with a 5-minute lifetime — any longer is risky for a bearer token.
        self._store_response_token(
            response_token,
            {**verdict, "expires_at": time.time() + 300},
        )

        return {**verdict, "response_token": response_token}

    def consume_response_token(self, response_token: str, site_key: str) -> dict[str, Any] | None:
        with self._response_tokens_lock:
            v = self._response_tokens.get(response_token)
            if v is None:
                return None
            # Validate before consuming so a wrong-secret call cannot burn
            # another site's token.
            if v.get("site_key") != site_key:
                return None
            if v.get("expires_at", 0) < time.time():
                self._response_tokens.pop(response_token, None)
                return None
            # All checks pass — consume atomically.
            return self._response_tokens.pop(response_token, None)

    # --- introspection ------------------------------------------------------ #

    def stats(self) -> dict:
        s = self.db.stats()
        s["sites"] = len(self.sites.list())
        return s

    def all_tier_policies(self) -> list[TierPolicy]:
        return [POLICIES[t] for t in (Tier.BASIC, Tier.STANDARD, Tier.PREMIUM)]
