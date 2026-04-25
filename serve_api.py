"""Standalone entry point for the PROOF public HTTP API.

Binds the same FastAPI app to two local ports (5000 and 8081). Both are
declared in `.replit` as `externalPort = 80`, so the Replit application
router may forward external HTTPS traffic to either upstream. Serving the
same app on both ports guarantees no 502 regardless of which upstream the
router picks for a given request.
"""
from __future__ import annotations

import asyncio
import os
import signal

import uvicorn

from proof_protocol.protocol import ProofProtocol
from proof_protocol.public_api import build_app


protocol = ProofProtocol(data_dir=os.environ.get("PROOF_DATA_DIR", "data"))
app = build_app(protocol)


def _make_server(port: int) -> uvicorn.Server:
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True,
        loop="asyncio",
    )
    return uvicorn.Server(config)


async def _serve_all(ports: list[int]) -> None:
    servers = [_make_server(p) for p in ports]

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_stop() -> None:
        stop_event.set()
        for s in servers:
            s.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except NotImplementedError:
            pass

    serve_tasks = [asyncio.create_task(s.serve()) for s in servers]
    await asyncio.gather(*serve_tasks)


def main() -> None:
    primary = int(os.environ.get("PORT", "5000"))
    extra_raw = os.environ.get("EXTRA_PORTS", "8081")
    extras = [int(p) for p in extra_raw.split(",") if p.strip()]

    ports: list[int] = []
    for p in [primary, *extras]:
        if p not in ports:
            ports.append(p)

    asyncio.run(_serve_all(ports))


if __name__ == "__main__":
    main()
