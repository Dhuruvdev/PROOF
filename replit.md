# PROOF — The UPI of Human Verification

A pure-Python reference implementation of the **PROOF Protocol**: a portable,
device-bound, zero-knowledge proof of humanity that replaces CAPTCHA. It
matches the production-grade signal class of Cloudflare Turnstile,
hCaptcha and reCAPTCHA v3 — every component is real, no mockups.

## What's running

* **PROOF Widget / Public HTTP API** — workflow `Start application`, port 5000.
  FastAPI + uvicorn. The only UI surface is the verification interstitial at
  `/`; all other routes are JSON / JS API endpoints:
  - `GET  /`                       — Cloudflare-style verification interstitial
                                     (the only HTML page; success/failure are
                                     revealed inline on the same page)
  - `GET  /api/health`             — liveness probe
  - `GET  /api/widget.js`          — drop-in JS bundle (Turnstile-shaped API)
  - `GET  /api/challenge?sitekey=` — issue PoW challenge
  - `POST /api/siteverify-front`   — browser → PROOF Network (PoW + telemetry → verdict)
  - `POST /api/siteverify`         — site backend → PROOF Network (Turnstile-shaped body)
  - `GET  /favicon.ico`            — empty 204 (silence browser noise)

Every signal is real — no mocks. The interstitial pipeline runs:

1. Real SHA-256 proof-of-work, adaptive 8–26 bit difficulty, HMAC-bound to
   the issuing server (cannot be downgraded by the client)
2. Real 27-feature browser-environment telemetry: canvas / WebGL / audio
   fingerprint, font enumeration, automation-surface probes (webdriver,
   _phantom, $cdc_*, playwright, puppeteer…), WebRTC local-IP probe,
   pointer-jitter intervals
3. Real IsolationForest anomaly model (trained at startup on a 600-sample
   synthetic human population) + weighted rule ensemble → Cloudflare
   four-path verdict (`ALLOW / ALLOW_WITH_INTERACTION / CHALLENGE / BLOCK`)
4. Real one-time response token (5 min TTL, single-consume, site-scoped)

Hardening on every response:
- Strict CSP (`default-src 'self'`, `frame-ancestors 'none'`)
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` denies camera / mic / geolocation / payment
- `/` is `Cache-Control: no-store` so each load mints a fresh Ray ID + challenge

The previous Streamlit admin UI and the `/protected` demo page have been
removed; the project now ships only the interstitial + public API surface.

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
