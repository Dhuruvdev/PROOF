# PROOF — The UPI of Human Verification

A pure-Python reference implementation of the **PROOF Protocol**: a portable,
device-bound, zero-knowledge proof of humanity that replaces CAPTCHA with a
sovereign, NPCI-style verification layer.

## Stack

- **Language**: Python 3.11
- **UI**: Streamlit (`app.py`, port 5000)
- **Storage**: SQLite (`data/proof.sqlite`) + per-device sealed enclave blobs
  under `data/enclaves/`
- **Crypto**: Pure-Python secp256k1 (Pedersen commitments, Schnorr ZK proofs,
  Sigma protocol via Fiat–Shamir) + `cryptography` library for AES-256-GCM
  and PBKDF2

## Layout

```
app.py                        Streamlit UI (6 pages: overview / enroll / issue /
                              verify / network / admin / audit)
proof_protocol/
  crypto_primitives.py        secp256k1 ECC, hash-to-curve, hash-to-scalar
  pedersen.py                 Pedersen commitments
  schnorr_zkp.py              Schnorr signature + Sigma proof of commitment
                              knowledge (Fiat–Shamir non-interactive)
  behavioral_dna.py           10-D feature vector: dwell, flight, entropy,
                              8–12 Hz tremor power (Welch PSD)
  secure_enclave.py           AES-256-GCM seal/unseal; PBKDF2-derived key;
                              device-fingerprint binding
  validator_network.py        Open validator pool + 2/3 quorum + signed
                              attestation chain
  trust_tiers.py              BASIC / STANDARD / PREMIUM policy
  database.py                 SQLite schema + thread-safe wrapper
  protocol.py                 End-to-end orchestration (enroll, issue, verify,
                              revoke, link-premium)
  self_test.py                Cryptographic & end-to-end test harness
.streamlit/config.toml        Server bound to 0.0.0.0:5000, headless
data/                         Persistent SQLite + sealed enclave blobs
```

## Commands

- Run the app: `streamlit run app.py --server.port 5000`
  (already wired into the **Start application** workflow)
- Run the self-test: `python -m proof_protocol.self_test`

## Cryptographic guarantees verified by the self-test

- secp256k1 keypair / scalar-mult correctness
- Schnorr signature soundness + tamper rejection
- Pedersen commitment binding
- ZK Sigma proof: zero-knowledge accepted on right context, rejected on
  modified context
- End-to-end: enrollment, token issuance, 4-validator quorum acceptance,
  tampered signature rejection, device-spoof rejection, revocation,
  premium-tier gating without identity link, audit log captures every event
