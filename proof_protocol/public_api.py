"""Public HTTP API for the PROOF Network.

Mirrors the Cloudflare Turnstile / reCAPTCHA / hCaptcha integration
contract so any web application can adopt PROOF with a one-line widget +
one server-side ``/siteverify`` POST.

Endpoints
---------

GET  /api/health
        Liveness probe.
GET  /api/widget.js
        The drop-in JS bundle (see widget_js.py).
GET  /api/challenge?sitekey=...
        Issue a fresh PoW challenge bound to the site.
POST /api/siteverify-front
        Browser → PROOF Network: submits {sitekey, challenge, solution,
        telemetry}; receives a one-time *response_token* the relying-party
        backend then verifies via /api/siteverify.
POST /api/siteverify
        Site backend → PROOF Network: {secret, response} → {success,
        action, score, hostname, ts, reasons[]}. Cloudflare-compatible
        body shape.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from .proof_of_work import PowChallenge, PowSolution
from .protocol import ProofProtocol
from .risk_engine import Action
from .telemetry import analyze
from .widget_js import widget_javascript


def build_app(protocol: ProofProtocol) -> FastAPI:
    app = FastAPI(title="PROOF Network — Public API", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "stats": protocol.stats(), "ts": time.time()}

    @app.get("/api/widget.js", response_class=PlainTextResponse)
    def widget(request: Request) -> str:
        base = str(request.base_url).rstrip("/")
        return widget_javascript(base)

    @app.get("/api/challenge")
    def challenge(sitekey: str = Query(...)) -> dict[str, Any]:
        site = protocol.sites.get(sitekey)
        if not site or not site.active:
            raise HTTPException(status_code=400, detail="invalid or inactive sitekey")
        ch = protocol.pow.issue(risk_score=0.0)
        return ch.to_dict()

    @app.post("/api/siteverify-front")
    async def siteverify_front(request: Request) -> dict[str, Any]:
        body = await request.json()
        sitekey = body.get("sitekey", "")
        site = protocol.sites.get(sitekey)
        if not site or not site.active:
            raise HTTPException(status_code=400, detail="invalid or inactive sitekey")

        try:
            challenge = PowChallenge.from_dict(body["challenge"])
            solution = PowSolution(
                challenge_id=body["solution"]["challenge_id"],
                nonce=int(body["solution"]["nonce"]),
                elapsed_seconds=float(body["solution"]["elapsed_seconds"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=f"malformed submission: {exc}")

        telemetry_summary = analyze(body.get("telemetry") or {})
        decision = protocol.evaluate_visitor(
            site_key=sitekey,
            challenge=challenge,
            solution=solution,
            telemetry=telemetry_summary,
            requester=site.domain,
        )

        return {
            "success": decision["success"],
            "token": decision.get("response_token", ""),
            "action": decision["action"],
            "score": decision["score"],
            "reasons": decision["reasons"][:6],
            "fingerprint": telemetry_summary.fingerprint,
        }

    @app.post("/api/siteverify")
    async def siteverify(request: Request) -> dict[str, Any]:
        # Accept either application/json or form-encoded (Turnstile-compatible)
        ctype = request.headers.get("content-type", "")
        if "application/json" in ctype:
            body = await request.json()
            secret = body.get("secret", "")
            response = body.get("response", "")
            remoteip = body.get("remoteip", "")
        else:
            form = await request.form()
            secret = str(form.get("secret", ""))
            response = str(form.get("response", ""))
            remoteip = str(form.get("remoteip", ""))

        site = protocol.sites.authenticate(secret)
        if not site:
            return {"success": False, "error-codes": ["invalid-input-secret"]}

        verdict = protocol.consume_response_token(response_token=response, site_key=site.site_key)
        if not verdict:
            return {"success": False, "error-codes": ["timeout-or-duplicate"]}

        return {
            "success": verdict["success"],
            "challenge_ts": verdict["ts"],
            "hostname": site.domain,
            "action": verdict["action"],
            "score": verdict["score"],
            "fingerprint": verdict["fingerprint"],
            "reasons": verdict["reasons"][:6],
            "error-codes": [] if verdict["success"] else ["bot-or-low-confidence"],
        }

    return app
