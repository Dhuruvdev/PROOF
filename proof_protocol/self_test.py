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
from .proof_of_work import ProofOfWorkIssuer, solve, _meets_difficulty
from .protocol import ProofProtocol, Tier
from .replay_protection import ReplayGuard
from .risk_engine import Action, anomaly_score, evaluate as risk_evaluate
from .schnorr_zkp import (
    prove_commitment_knowledge,
    schnorr_sign,
    schnorr_verify,
    verify_commitment_knowledge,
)
from .telemetry import analyze


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

        # ----- Phase 2: PoW + telemetry + risk engine + sites ---------------

        # Hashcash: forged challenge MAC must be rejected
        pow_issuer = ProofOfWorkIssuer(secret_key=b"X" * 32, base_difficulty=12)
        ch = pow_issuer.issue()
        sol = solve(ch)
        ok, why = pow_issuer.verify(ch, sol)
        assert ok, why
        # Lower difficulty advertised by client must fail MAC check
        from .proof_of_work import PowChallenge
        forged = PowChallenge(challenge_id=ch.challenge_id, difficulty=4,
                              issued_at=ch.issued_at, expires_at=ch.expires_at,
                              issuer_mac=ch.issuer_mac)
        ok2, _ = pow_issuer.verify(forged, sol)
        assert not ok2, "downgraded-difficulty challenge should fail MAC"
        # And the underlying primitive itself
        assert _meets_difficulty(ch.challenge_id, sol.nonce, ch.difficulty)
        print(f" [ok] proof-of-work issued, solved (nonce={sol.nonce}, "
              f"difficulty={ch.difficulty}), MAC-tamper rejected")

        # Telemetry: clean human vs headless bot
        clean = analyze({
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/138.0.0.0 Safari/537.36",
            "languages": ["en-US","en"], "languagesCount": 2,
            "pluginsCount": 5, "hardwareConcurrency": 8, "deviceMemory": 8,
            "screenWidth": 1920, "screenHeight": 1080, "timezone": "Asia/Kolkata",
            "timezoneOffsetMinutes": 330, "webdriver": False, "chromeRuntime": True,
            "automationProps": [],
            # Realistic uniformly-distributed SHA-256 hex (a real GPU canvas FP):
            "canvasHash": "9f1c6a37b04e8d215c70a9e3f8b62d4a7e15c980fa3d6b2c47e91ab305f8d6c2",
            "webglRenderer": "NVIDIA RTX 4070", "webglVendor": "NVIDIA",
            "audioHash": "a7e2b48c1d9f5063e7c12a48b9d0f5e2", "fontsDetected": 32,
            "rtcLocalIp": "192.168.1.27",
            "pointerIntervalsMs": [12,14,9,22,18,15,11,19,13,17,21],
            "scrollCount": 6, "focusEvents": 2, "challengeSolveMs": 180,
            "requestAgeSeconds": 0.8, "batteryPresent": True,
        })
        bot = analyze({
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/138.0.0.0",
            "languages": [], "languagesCount": 0,
            "pluginsCount": 0, "hardwareConcurrency": 2, "deviceMemory": 0,
            "screenWidth": 800, "screenHeight": 600, "timezone": "UTC",
            "timezoneOffsetMinutes": 0, "webdriver": True, "chromeRuntime": False,
            "automationProps": ["webdriver","__playwright","puppeteer"],
            "canvasHash": "", "webglRenderer": "Google SwiftShader",
            "webglVendor": "Google Inc.", "audioHash": "",
            "fontsDetected": 1, "rtcLocalIp": "",
            "pointerIntervalsMs": [], "scrollCount": 0, "focusEvents": 0,
            "challengeSolveMs": 2, "requestAgeSeconds": 0.05,
        })
        assert clean.suspicion_score < 20, f"clean score too high: {clean.suspicion_score}"
        assert bot.suspicion_score > 70, f"bot score too low: {bot.suspicion_score}"
        assert any("HeadlessChrome" in f or "headless" in f.lower() for f in bot.risk_flags)
        assert any("webdriver" in f.lower() for f in bot.risk_flags)
        print(f" [ok] telemetry: clean={clean.suspicion_score:.0f}, bot={bot.suspicion_score:.0f}, "
              f"bot raised {len(bot.risk_flags)} flags")

        # Anomaly model is deterministic and ranks bots above humans
        a_clean = anomaly_score(clean.feature_vector)
        a_bot = anomaly_score(bot.feature_vector)
        assert a_bot > a_clean, f"anomaly should rank bot > clean (got {a_bot:.1f} vs {a_clean:.1f})"
        print(f" [ok] IsolationForest anomaly: clean={a_clean:.1f}, bot={a_bot:.1f}")

        # Risk engine end-to-end
        d_clean = risk_evaluate(clean, pow_solved=True, pow_elapsed_ms=180,
                                behavioral_distance=0.05, reputation_score=100,
                                replay_seen_before=False)
        d_bot = risk_evaluate(bot, pow_solved=False, pow_elapsed_ms=2,
                              behavioral_distance=None, reputation_score=20,
                              replay_seen_before=False)
        assert d_clean.action in (Action.ALLOW, Action.ALLOW_WITH_INTERACTION), \
            f"clean human got {d_clean.action} ({d_clean.score:.1f})"
        assert d_bot.action in (Action.CHALLENGE, Action.BLOCK), \
            f"bot got {d_bot.action} ({d_bot.score:.1f})"
        print(f" [ok] risk engine: clean→{d_clean.action.value} ({d_clean.score:.1f}), "
              f"bot→{d_bot.action.value} ({d_bot.score:.1f})")

        # Replay guard
        g = ReplayGuard(proto.db)
        n = "nonce-" + cp.sha256(b"x").hex()[:16]
        assert g.seen_or_record(n) is False
        assert g.seen_or_record(n) is True
        print(" [ok] replay guard catches nonce reuse")

        # Site registration + end-to-end /siteverify-front + /siteverify
        site = proto.sites.register(label="Self-Test", domain="selftest.example")
        assert site.site_key.startswith("0x4PROOF")
        ch2 = proto.pow.issue()
        sol2 = solve(ch2)
        verdict = proto.evaluate_visitor(
            site_key=site.site_key, challenge=ch2, solution=sol2,
            telemetry=clean, requester="selftest.example",
        )
        assert verdict["success"], f"clean visitor rejected: {verdict['reasons']}"
        rt = verdict["response_token"]
        # Wrong secret → invalid
        assert proto.consume_response_token(rt, site_key="not-the-key") is None
        # First consumption succeeds
        consumed = proto.consume_response_token(rt, site_key=site.site_key)
        assert consumed and consumed["success"]
        # Replay — second consumption must fail (one-time token)
        assert proto.consume_response_token(rt, site_key=site.site_key) is None
        print(f" [ok] site verification round-trip: action={verdict['action']}, "
              f"score={verdict['score']:.1f}, response_token one-time")

        # Bot path through the same evaluator must NOT be successful
        ch3 = proto.pow.issue()
        sol3 = solve(ch3)
        bot_verdict = proto.evaluate_visitor(
            site_key=site.site_key, challenge=ch3, solution=sol3,
            telemetry=bot, requester="selftest.example",
        )
        assert not bot_verdict["success"], \
            f"bot was accepted (action={bot_verdict['action']}, score={bot_verdict['score']:.1f})"
        print(f" [ok] bot blocked end-to-end: action={bot_verdict['action']}, "
              f"score={bot_verdict['score']:.1f}")

        print()
        print("All self-tests passed.")
        return 0

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
