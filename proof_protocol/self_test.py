"""End-to-end self-test for the PROOF Protocol.

Run with ``python -m proof_protocol.self_test``. Exits with a non-zero
status if any cryptographic invariant is violated.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

from . import crypto_primitives as cp
from .pedersen import commit, verify_opening
from .protocol import ProofProtocol, Tier
from .schnorr_zkp import (
    prove_commitment_knowledge,
    schnorr_sign,
    schnorr_verify,
    verify_commitment_knowledge,
)


def _synthetic_keystrokes(seed: int = 0, count: int = 30) -> list[dict]:
    """Generate a deterministic but human-plausible event stream."""
    import random
    rng = random.Random(seed)
    t = 1_000_000.0
    events = []
    for _ in range(count):
        dwell = rng.uniform(0.04, 0.12)
        flight = rng.uniform(0.03, 0.18)
        events.append({"key": rng.choice("abcdefghijklmnop"), "down": t, "up": t + dwell})
        t += dwell + flight
    return events


def main() -> int:
    print("PROOF Protocol self-test")
    print("=" * 60)

    # 1. ECC sanity
    sk, pk = cp.keypair()
    assert pk == cp.scalar_mult(sk, cp.G)
    print(" [ok] secp256k1 keypair")

    # 2. Schnorr signature
    sig = schnorr_sign(sk, b"hello")
    assert schnorr_verify(pk, b"hello", sig)
    assert not schnorr_verify(pk, b"tampered", sig)
    print(" [ok] Schnorr signature soundness + tampering rejection")

    # 3. Pedersen commitment binding/hiding
    msg = cp.random_scalar()
    c = commit(msg)
    assert verify_opening(c.point, msg, c.randomness)
    assert not verify_opening(c.point, msg + 1, c.randomness)
    print(" [ok] Pedersen commitment binding")

    # 4. ZK proof of commitment knowledge
    zk = prove_commitment_knowledge(msg, c.randomness, c.point, context=b"ctx")
    assert verify_commitment_knowledge(c.point, zk, context=b"ctx")
    assert not verify_commitment_knowledge(c.point, zk, context=b"different")
    print(" [ok] Sigma proof: zero knowledge of (m, r) accepted; tampered context rejected")

    # 5. End-to-end protocol with persistent state
    workdir = Path(tempfile.mkdtemp(prefix="proof-selftest-"))
    try:
        proto = ProofProtocol(workdir)
        proto.network.add_validator("NPCI-Mumbai", "ap-south-1")
        proto.network.add_validator("Gov-of-India", "ap-south-1")
        proto.network.add_validator("Aadhaar-CIDR", "ap-south-1")
        proto.network.add_validator("Reliance-Jio", "ap-south-1")

        machine_signals = {"ua": "PROOF-self-test", "screen": "1920x1080", "tz": "Asia/Kolkata"}
        passphrase = "correct horse battery staple"

        events = _synthetic_keystrokes(seed=42)
        enrollment, bv = proto.enroll_device(machine_signals, passphrase, events)
        print(f" [ok] enrolled device {enrollment.device_id}")

        # Issue a token using a *fresh* capture from the same generator seed.
        live_events = _synthetic_keystrokes(seed=42)
        token, live_bv, distance = proto.issue_token(
            device_id=enrollment.device_id,
            passphrase=passphrase,
            raw_events=live_events,
            tier=Tier.BASIC,
            relying_party_challenge=b"example.com:login:42",
        )
        print(f" [ok] issued token {token.token_id} at distance {distance:.4f}")

        # Verify via quorum
        result = proto.verify_token(token, requester="example.com")
        assert result.valid, f"verification should succeed, failure: {result.failure_reason}"
        print(f" [ok] quorum {result.yes}/{result.total} accepted token")

        # Tamper detection: flip a bit in the signature
        token.device_signature = type(token.device_signature)(R=token.device_signature.R, s=token.device_signature.s ^ 1)
        bad = proto.verify_token(token, requester="example.com")
        assert not bad.valid
        print(f" [ok] tampered signature rejected ({bad.failure_reason})")

        # Replay across a *different* device's commitment fails
        other_signals = {"ua": "OTHER", "screen": "800x600", "tz": "UTC"}
        other_events = _synthetic_keystrokes(seed=999)
        proto.enroll_device(other_signals, "another passphrase", other_events)
        # Get the original token back from DB and try to verify (not tampered now)
        # First restore the signature
        live_events2 = _synthetic_keystrokes(seed=42)
        token2, _, _ = proto.issue_token(
            device_id=enrollment.device_id,
            passphrase=passphrase,
            raw_events=live_events2,
            tier=Tier.BASIC,
            relying_party_challenge=b"example.com:login:43",
        )
        # Mutate the device_id to point at another device — verification must fail.
        token2.device_id = cp.sha256(b"some-other-device").hex()[:32]
        spoof = proto.verify_token(token2, requester="example.com")
        assert not spoof.valid
        print(f" [ok] device-spoofed token rejected ({spoof.failure_reason})")

        # Revocation
        live_events3 = _synthetic_keystrokes(seed=42)
        token3, _, _ = proto.issue_token(
            device_id=enrollment.device_id,
            passphrase=passphrase,
            raw_events=live_events3,
            tier=Tier.BASIC,
            relying_party_challenge=b"example.com:login:44",
        )
        proto.revoke_token(token3.token_id, "user-requested")
        revoked = proto.verify_token(token3, requester="example.com")
        assert not revoked.valid and revoked.failure_reason == "token revoked"
        print(" [ok] revoked token rejected by quorum")

        # Premium tier blocked without identity link
        try:
            live_events4 = _synthetic_keystrokes(seed=42)
            proto.issue_token(
                device_id=enrollment.device_id,
                passphrase=passphrase,
                raw_events=live_events4,
                tier=Tier.PREMIUM,
                relying_party_challenge=b"bank.example:login",
            )
            assert False, "premium without identity should have failed"
        except PermissionError as exc:
            print(f" [ok] premium blocked without identity link ({exc})")

        # Link premium and retry
        proto.link_premium_identity(
            enrollment.device_id,
            aadhaar="1234 5678 9012",
            upi_handle="user@upi",
            digilocker_id="DL-XXX",
        )
        live_events5 = _synthetic_keystrokes(seed=42)
        premium_token, _, _ = proto.issue_token(
            device_id=enrollment.device_id,
            passphrase=passphrase,
            raw_events=live_events5,
            tier=Tier.PREMIUM,
            relying_party_challenge=b"bank.example:login",
        )
        ok = proto.verify_token(premium_token, requester="bank.example")
        assert ok.valid
        print(f" [ok] premium token issued and accepted ({ok.yes}/{ok.total})")

        # Audit log non-empty
        rows = proto.db.recent_audit(limit=20)
        assert len(rows) >= 5
        print(f" [ok] audit log captured {len(rows)} events")

        print()
        print("All self-tests passed.")
        return 0

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
