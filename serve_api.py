"""Standalone entry point for the PROOF public HTTP API.

Binds the same FastAPI app to two local ports (5000 and 8081). Both are
declared in `.replit` as `externalPort = 80`, so the Replit application
router may forward external HTTPS traffic to either upstream. Serving the
same app on both ports guarantees no 502 regardless of which upstream the
router picks for a given request.
"""
from __future__ import annotations

import os
import threading

import uvicorn

from proof_protocol.protocol import ProofProtocol
from proof_protocol.public_api import build_app


protocol = ProofProtocol(data_dir=os.environ.get("PROOF_DATA_DIR", "data"))
app = build_app(protocol)


def _run_secondary(port: int) -> None:
    import asyncio

    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    asyncio.run(server.serve())


def main() -> None:
    primary = int(os.environ.get("PORT", "5000"))
    extra_raw = os.environ.get("EXTRA_PORTS", "8081")
    extras = [int(p) for p in extra_raw.split(",") if p.strip() and int(p) != primary]

    for p in extras:
        t = threading.Thread(target=_run_secondary, args=(p,), daemon=True, name=f"uvicorn-{p}")
        t.start()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=primary,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
