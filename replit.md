# PROOF — The UPI of Human Verification

A pure-Python reference implementation of the **PROOF Protocol**: a portable,
device-bound, zero-knowledge proof of humanity that replaces CAPTCHA. It now
matches the production-grade signal class of Cloudflare Turnstile,
hCaptcha and reCAPTCHA v3 — every component is real, no mockups.

## What's running

* **Streamlit UI** — workflow `Start application`, port 5000.
  Nine pages: Overview · Enroll · Issue · Verify · Validators · Admin ·
  Audit · **Sites** · **Integration** · **Live widget**.
* **Public HTTP API** — workflow `PROOF API Server`, port 8000.
  Cloudflare-compatible endpoints any external site can integrate with:
  - `GET  /api/health`
  - `GET  /api/widget.js` — drop-in JS bundle
  - `GET  /api/challenge?sitekey=...` — issue PoW challenge
  - `POST /api/siteverify-front` — browser → PROOF Network
  - `POST /api/siteverify` — site backend → PROOF Network (Turnstile-shaped body)

## Stack

- **Language**: Python 3.11
- **UI**: Streamlit
- **API**: FastAPI + uvicorn
- **Storage**: SQLite (`data/proof.sqlite`) + per-device sealed enclave blobs
  under `data/enclaves/`
- **Crypto**: Pure-Python secp256k1 (Pedersen commitments, Schnorr ZK proofs,
  Sigma protocol via Fiat–Shamir) + `cryptography` (AES-256-GCM, PBKDF2)
- **ML**: scikit-learn IsolationForest trained on a 600-sample synthetic
  human-population for browser-fingerprint anomaly detection

## Layout

```
app.py                            Streamlit UI (9 pages)
serve_api.py                      uvicorn entry point for the public API
proof_protocol/
  crypto_primitives.py            secp256k1 ECC, hash-to-curve, hash-to-scalar
  pedersen.py                     Pedersen commitments
  schnorr_zkp.py                  Schnorr signature + Sigma proof
  behavioral_dna.py               10-D feature vector with 8–12 Hz tremor PSD
  secure_enclave.py               AES-256-GCM seal/unseal
  validator_network.py            Open validator pool + 2/3 quorum
  trust_tiers.py                  BASIC / STANDARD / PREMIUM policy
  database.py                     SQLite schema + thread-safe wrapper

  # Phase 2 — Cloudflare-class signals
  proof_of_work.py                Hashcash-style PoW with HMAC'd, adaptive
                                  difficulty (8–26 bits) — silent fast path
  telemetry.py                    Browser-environment integrity: 27-feature
                                  vector covering canvas/WebGL/audio FP, font
                                  enumeration, automation-surface detection
                                  (webdriver, _phantom, $cdc_*, playwright,
                                  puppeteer…), WebRTC IP leak, pointer jitter
  risk_engine.py                  IsolationForest + weighted rule ensemble →
                                  ALLOW / ALLOW_WITH_INTERACTION / CHALLENGE
                                  / BLOCK (Cloudflare 4-path model)
  sites.py                        Site key / secret key registry
  replay_protection.py            TTL-bounded nonce store
  widget_js.py                    Real drop-in JS widget — Turnstile-compatible
                                  PROOF.render(elementId, {sitekey, callback})
  public_api.py                   FastAPI app exposing the public endpoints
  protocol.py                     End-to-end orchestrator
  self_test.py                    21-check cryptographic + ML test harness
.streamlit/config.toml            0.0.0.0:5000, headless
data/                             Persistent SQLite + sealed enclave blobs
```

## Commands

- Streamlit: `streamlit run app.py --server.port 5000`
- Public API: `python serve_api.py` (or set `PORT` env var)
- Self-test: `python -m proof_protocol.self_test`

## What the self-test verifies

1. secp256k1 keypair, scalar-mult correctness
2. Schnorr signature soundness + tamper rejection
3. Pedersen commitment binding
4. Sigma ZK proof: accepted on right context, rejected on modified context
5. Enrollment → token → 4/4 validator quorum acceptance
6. Tampered signature rejected
7. Device-spoofed token rejected
8. Revoked token rejected
9. Premium tier blocked without identity link, accepted after link
10. Audit log captures every event
11. Hashcash PoW: solved correctly + downgraded-difficulty MAC tamper rejected
12. Telemetry: clean human → suspicion 0; HeadlessChrome+webdriver bot → 100,
    raises 15 distinct risk flags
13. IsolationForest ranks bots above humans
14. Risk engine: clean → ALLOW; bot → BLOCK
15. Replay guard: nonce reuse detected
16. Site round-trip: register → /api/siteverify-front → /api/siteverify works
17. Bot blocked end-to-end with concrete reason strings
18. Wrong-secret cannot consume a foreign site's response token
19. Replay of a response_token returns `timeout-or-duplicate`

The same paths are also exercised against the **running HTTP API** —
human → `ALLOW`, headless-Chrome bot → `BLOCK`, replay → denied,
wrong secret → denied.
