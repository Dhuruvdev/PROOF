"""Standalone entry point for the PROOF public HTTP API."""
from __future__ import annotations

import os

import uvicorn

from proof_protocol.protocol import ProofProtocol
from proof_protocol.public_api import build_app


protocol = ProofProtocol(data_dir=os.environ.get("PROOF_DATA_DIR", "data"))
app = build_app(protocol)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
