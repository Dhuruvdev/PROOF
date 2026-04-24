"""Software-emulated secure enclave.

In production this would be a hardware-backed TEE (Apple Secure Enclave,
Android Strongbox, ARM TrustZone, India-stack HSM). Here we implement an
equivalent *software* interface using AES-256-GCM with the encryption key
derived from a per-device passphrase via PBKDF2-HMAC-SHA256 with 200 000
iterations and a 16-byte random salt.

Key properties replicated from a real enclave:

* Keys never leave the enclave object.
* Sealed blobs are bound to a stable device fingerprint; moving the
  encrypted file to another device renders it unopenable.
* The enclave exposes only ``seal`` / ``unseal`` / ``sign`` operations.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import crypto_primitives as cp
from .schnorr_zkp import SchnorrSig, schnorr_sign


PBKDF2_ITERATIONS = 200_000
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12


@dataclass
class SealedBlob:
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    device_tag: bytes  # MAC over device fingerprint bound to this blob

    def to_dict(self) -> dict:
        return {
            "salt": self.salt.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "device_tag": self.device_tag.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SealedBlob":
        return cls(
            salt=bytes.fromhex(d["salt"]),
            nonce=bytes.fromhex(d["nonce"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
            device_tag=bytes.fromhex(d["device_tag"]),
        )


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase)


class SecureEnclave:
    """A device-bound enclave protecting one device key + arbitrary blobs."""

    def __init__(self, device_id: str, passphrase: str, storage_dir: str | os.PathLike[str]):
        self._device_id = device_id
        self._passphrase = passphrase.encode("utf-8")
        self._dir = Path(storage_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._key_path = self._dir / f"{device_id}.enclave.json"

        # Long-lived device key (a secp256k1 scalar) is generated lazily and
        # then sealed at rest.
        self._device_sk: int | None = None
        self._device_pk: cp.Point | None = None
        self._load_or_init_device_key()

    # --- public API --------------------------------------------------------- #

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def device_public_key(self) -> cp.Point:
        assert self._device_pk is not None
        return self._device_pk

    def sign(self, message: bytes) -> SchnorrSig:
        """Schnorr-sign with the enclave-resident device key."""
        assert self._device_sk is not None
        return schnorr_sign(self._device_sk, message)

    def seal(self, plaintext: bytes) -> SealedBlob:
        salt = secrets.token_bytes(SALT_LEN)
        key = _derive_key(self._passphrase, salt)
        nonce = secrets.token_bytes(NONCE_LEN)
        aad = self._device_id.encode("utf-8")
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        device_tag = cp.sha256(self._device_id.encode("utf-8") + salt + nonce + ct)
        return SealedBlob(salt=salt, nonce=nonce, ciphertext=ct, device_tag=device_tag)

    def unseal(self, blob: SealedBlob) -> bytes:
        expected_tag = cp.sha256(
            self._device_id.encode("utf-8") + blob.salt + blob.nonce + blob.ciphertext
        )
        if not secrets.compare_digest(expected_tag, blob.device_tag):
            raise PermissionError("Sealed blob is bound to a different device — refusing to open")
        key = _derive_key(self._passphrase, blob.salt)
        aad = self._device_id.encode("utf-8")
        try:
            return AESGCM(key).decrypt(blob.nonce, blob.ciphertext, aad)
        except Exception as exc:  # noqa: BLE001 — wrap into a typed error
            raise PermissionError("Unable to unseal: wrong passphrase or corrupted blob") from exc

    def store_named(self, name: str, plaintext: bytes) -> None:
        blob = self.seal(plaintext)
        path = self._dir / f"{self._device_id}.{name}.blob.json"
        path.write_text(json.dumps(blob.to_dict()))

    def load_named(self, name: str) -> bytes:
        path = self._dir / f"{self._device_id}.{name}.blob.json"
        if not path.exists():
            raise FileNotFoundError(name)
        blob = SealedBlob.from_dict(json.loads(path.read_text()))
        return self.unseal(blob)

    def has_named(self, name: str) -> bool:
        return (self._dir / f"{self._device_id}.{name}.blob.json").exists()

    # --- private helpers ---------------------------------------------------- #

    def _load_or_init_device_key(self) -> None:
        if self._key_path.exists():
            blob = SealedBlob.from_dict(json.loads(self._key_path.read_text()))
            sk_bytes = self.unseal(blob)
            self._device_sk = int.from_bytes(sk_bytes, "big") % cp.N
        else:
            self._device_sk = cp.random_scalar()
            blob = self.seal(self._device_sk.to_bytes(32, "big"))
            self._key_path.write_text(json.dumps(blob.to_dict()))
        self._device_pk = cp.scalar_mult(self._device_sk, cp.G)


def derive_device_id(machine_signals: dict[str, Any]) -> str:
    """Hash a bag of machine signals into a stable 32-hex-char device ID."""
    payload = json.dumps(machine_signals, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return cp.sha256(payload).hex()[:32]
