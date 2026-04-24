# PROOF — The UPI of Human Verification

A pure-Python reference implementation of the **PROOF Protocol**: a portable,
device-bound, zero-knowledge proof of humanity that replaces CAPTCHA. It
matches the production-grade signal class of Cloudflare Turnstile,
hCaptcha and reCAPTCHA v3 — every component is real, no mockups.

## What's running

* **PROOF Widget / Public HTTP API** — workflow `Start application`, port 5000.
  FastAPI + uvicorn. Cloudflare-compatible endpoints any external site can
  integrate with, plus a built-in interstitial demo:
  - `GET  /`                       — demo home with "Open" button
  - `GET  /verify`                 — Cloudflare-style verification interstitial
  - `GET  /protected`              — page behind the interstitial
  - `GET  /api/health`
  - `GET  /api/widget.js`          — drop-in JS bundle
  - `GET  /api/challenge?sitekey=` — issue PoW challenge
  - `POST /api/siteverify-front`   — browser → PROOF Network
  - `POST /api/siteverify`         — site backend → PROOF Network (Turnstile-shaped body)

The previous Streamlit admin UI has been removed; the project now ships only
the widget + public API surface.

## Stack

- **Language**: Python 3.11
- **API**: FastAPI + uvicorn
- **Storage**: SQLite (`data/proof.sqlite`) + per-device sealed enclave blobs
  under `data/enclaves/`
- **Crypto**: Pure-Python secp256k1 (Pedersen commitments, Schnorr ZK proofs,
  Sigma protocol via Fiat–Shamir) + `cryptography` (AES-256-GCM, PBKDF2)
- **ML**: scikit-learn IsolationForest trained on a 600-sample synthetic
  human-population for browser-fingerprint anomaly detection

## Layout

```
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
data/                             Persistent SQLite + sealed enclave blobs
```

## Commands

- Public API / widget: `python serve_api.py` (set `PORT` env var to override; default 5000)
- Self-test: `python -m proof_protocol.self_test`

## Recent changes

- **2026-04-24**: Removed the Streamlit admin UI (`app.py`, `.streamlit/`) and
  the `streamlit` dependency. The API server now binds to port 5000 by
  default and is the only running workflow. Site administration is still
  available programmatically via `proof_protocol.sites` or by extending the
  FastAPI app.
