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

import html
import json
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .proof_of_work import PowChallenge, PowSolution
from .protocol import ProofProtocol
from .risk_engine import Action
from .telemetry import analyze
from .widget_js import widget_javascript


# --------------------------------------------------------------------------- #
# Cloudflare-style "Performing security verification" interstitial
# --------------------------------------------------------------------------- #

_INTERSTITIAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>__HOSTNAME__</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  html, body { margin:0; padding:0; background:#1c1c1c; color:#f1f1f1;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif; min-height:100vh; }
  .wrap { padding: 28px 22px 120px; max-width: 760px; }
  h1 { font-size: 30px; font-weight: 600; margin: 16px 0 18px;
       word-break: break-all; line-height: 1.2; }
  h2 { font-size: 22px; font-weight: 500; margin: 0 0 14px; color: #f1f1f1; }
  p.desc { color:#c8c8c8; font-size: 16px; line-height: 1.55;
           max-width: 560px; margin: 0 0 22px; }
  .panel { background:#2b2b2b; border-radius:6px; padding:14px 18px;
           max-width: 520px; display:flex; align-items:center;
           justify-content:space-between; gap:18px; min-height:54px; }
  .left  { display:flex; align-items:center; gap:14px; }
  .right { text-align:right; font-size:11px; color:#9aa1a6; line-height:1.4; }
  .right .brand { font-weight: 800; letter-spacing:.06em;
                  color:#fff; font-size:13px; }
  .right .brand .dot { color:#f6821f; }
  .right a { color:#9aa1a6; text-decoration:none; }
  .right a:hover { text-decoration: underline; }
  #status { font-size: 16px; }
  /* 8-dot circular spinner — animation cycles through the ring */
  .spinner { width:34px; height:34px; }
  .spinner circle { fill:#3da25f; }
  .reasons { color:#ffb3b3; font-size:13px; margin: 14px 0 0;
             padding-left: 22px; max-width: 560px; display:none; }
  .reasons li { margin: 4px 0; }
  .panel.ok  { background:#0f3a1d; }
  .panel.err { background:#3a1414; }
  .footer { position:fixed; bottom:0; left:0; right:0; padding:18px 16px 22px;
            text-align:center; color:#a0a0a0; font-size: 13px;
            border-top: 1px solid #2a2a2a; background:#1c1c1c; }
  .footer a { color:#a0a0a0; }
  .meta { margin: 6px 0; }
  .timing { color:#9aa1a6; font-size:12px; margin-top:10px; max-width:520px; }
  .openbtn { display:inline-block; margin-top: 18px; background:#3da25f;
             color:#fff; padding: 9px 18px; border-radius: 4px;
             text-decoration:none; font-weight:600; font-size:14px; }
  .openbtn:hover { background:#48b96d; }
</style>
</head>
<body>
<div class="wrap">
  <h1>__HOSTNAME__</h1>
  <h2 id="title">Performing security verification</h2>
  <p class="desc" id="desc">This website uses a security service to protect
    against malicious bots. This page is displayed while the website verifies
    you are not a bot.</p>

  <div class="panel" id="panel">
    <div class="left">
      <svg class="spinner" id="spinner" viewBox="0 0 50 50">
        <circle cx="25" cy="6"    r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.00s" repeatCount="indefinite"/></circle>
        <circle cx="38.4" cy="11.5" r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.12s" repeatCount="indefinite"/></circle>
        <circle cx="44" cy="25"   r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.25s" repeatCount="indefinite"/></circle>
        <circle cx="38.4" cy="38.5" r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.37s" repeatCount="indefinite"/></circle>
        <circle cx="25" cy="44"   r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.50s" repeatCount="indefinite"/></circle>
        <circle cx="11.6" cy="38.5" r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.62s" repeatCount="indefinite"/></circle>
        <circle cx="6"  cy="25"   r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.75s" repeatCount="indefinite"/></circle>
        <circle cx="11.6" cy="11.5" r="4"><animate attributeName="opacity"
          values="1;0.15;0.15;1" dur="1.0s" begin="0.87s" repeatCount="indefinite"/></circle>
      </svg>
      <span id="status">Verifying...</span>
    </div>
    <div class="right">
      <div class="brand">PR<span class="dot">●</span>OF</div>
      <div><a href="#privacy">Privacy</a> &nbsp;·&nbsp; <a href="#help">Help</a></div>
    </div>
  </div>

  <ul class="reasons" id="reasons"></ul>
  <div class="timing" id="timing"></div>
</div>

<div class="footer">
  <div class="meta">Ray ID: <span id="rayid">__RAY_ID__</span></div>
  <div>Performance and Security by <a href="#">PROOF</a> &nbsp;|&nbsp;
       <a href="#">Privacy</a></div>
</div>

<script src="__API__/api/widget.js"></script>
<script>
(function() {
  const SITEKEY = __SITEKEY_JSON__;
  const DEST    = __DEST_JSON__;
  const RAY     = __RAY_JSON__;
  const tStart  = performance.now();

  function setStatus(t)  { document.getElementById('status').innerText = t; }
  function setTiming(ms) {
    document.getElementById('timing').innerText =
      'Completed in ' + ms.toFixed(0) + ' ms · Ray ID ' + RAY;
  }

  function done(result) {
    document.getElementById('panel').classList.add('ok');
    document.getElementById('spinner').style.display = 'none';
    setStatus('Verified — redirecting…');
    setTiming(performance.now() - tStart);
    const url = new URL(DEST, window.location.origin);
    url.searchParams.set('proof_token', result.token);
    url.searchParams.set('proof_sitekey', SITEKEY);
    url.searchParams.set('proof_ray', RAY);
    setTimeout(function() { window.location.href = url.toString(); }, 700);
  }

  function fail(result) {
    document.getElementById('title').innerText = 'Sorry, you have been blocked';
    document.getElementById('desc').innerText =
      'You are unable to access this page. Our automated security checks ' +
      'suggest your browser is not a real human user. If you believe this ' +
      'is in error, please contact the site owner with the Ray ID below.';
    document.getElementById('panel').classList.add('err');
    document.getElementById('spinner').style.display = 'none';
    setStatus('Blocked  ·  action=' + (result.action || 'BLOCK') +
              '  ·  score=' + (result.score || 0).toFixed(1));
    const ul = document.getElementById('reasons');
    ul.style.display = 'block';
    ul.innerHTML = '';
    (result.reasons || ['verification failed']).slice(0, 6).forEach(function(r) {
      const li = document.createElement('li'); li.innerText = r; ul.appendChild(li);
    });
    setTiming(performance.now() - tStart);
  }

  async function start() {
    if (!window.PROOF || !window.PROOF.verify) { setTimeout(start, 50); return; }
    try {
      // Real silent verification — same code path the embeddable widget uses.
      const r = await window.PROOF.verify(SITEKEY);
      if (r && r.success) { done(r); } else { fail(r || {}); }
    } catch (e) {
      fail({reasons: [String(e && e.message || e)]});
    }
  }
  start();
})();
</script>
</body>
</html>"""


_PROTECTED_OK_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>__HOSTNAME__ — verified</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { background:#0f1116; color:#e8eaed; margin:0; padding:32px;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .card { max-width: 720px; margin: 0 auto; background:#161a23;
          border-radius: 10px; padding: 28px; border:1px solid #232838; }
  h1 { margin:0 0 8px; font-size: 28px; }
  .ok { color: #6ee787; font-weight: 700; }
  table { width:100%; border-collapse: collapse; margin-top: 18px; font-size:14px; }
  th, td { text-align:left; padding: 8px 10px; border-bottom:1px solid #232838; }
  th { color:#9aa1a6; font-weight:500; width: 30%; }
  code { background:#0b1020; padding:2px 6px; border-radius:4px; color:#9ce39c; }
  .actions { margin-top: 22px; }
  a.btn { display:inline-block; background:#3da25f; color:#fff; padding:8px 16px;
          border-radius:4px; text-decoration:none; font-weight:600; }
</style></head>
<body><div class="card">
  <h1>__HOSTNAME__</h1>
  <p>Status: <span class="ok">✓ verified by PROOF</span></p>
  <p>This is the page that lives behind the verification interstitial. Your
     browser was just challenged with a real proof-of-work, profiled against
     the PROOF risk engine, and cleared as human traffic. The relying-party
     server consumed your one-time response token to show this page.</p>
  <table>
    <tr><th>Action</th><td><code>__ACTION__</code></td></tr>
    <tr><th>Risk score</th><td><code>__SCORE__</code> / 100 (lower is better)</td></tr>
    <tr><th>Browser fingerprint</th><td><code>__FP__</code></td></tr>
    <tr><th>Response token</th><td><code>__TOKEN__</code> &nbsp;<em>(burned — single-use)</em></td></tr>
    <tr><th>Ray ID</th><td><code>__RAY__</code></td></tr>
    <tr><th>Verified at</th><td><code>__TS__</code></td></tr>
  </table>
  <div class="actions">
    <a class="btn" href="/">← Back to demo home</a>
  </div>
</div></body></html>"""


_PROTECTED_FAIL_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Access denied</title>
<style>
  body { background:#0f1116; color:#e8eaed; margin:0; padding:32px;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .card { max-width: 720px; margin: 0 auto; background:#1f1010; border-radius: 10px;
          padding: 24px; border:1px solid #3a1818; }
  h1 { margin:0 0 8px; }
  .bad { color:#ff7b7b; font-weight: 700; }
  a { color:#9ec1ff; }
</style></head>
<body><div class="card">
  <h1>Access denied</h1>
  <p class="bad">__REASON__</p>
  <p>Your verification token could not be validated. This usually means it
     expired (5-minute lifetime), was already used, or was issued for a
     different site. <a href="__VERIFY_URL__">Try again</a>.</p>
</div></body></html>"""


_HOME_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>PROOF Network — demo</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { background:#0f1116; color:#e8eaed; margin:0; padding:48px 24px;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .card { max-width: 760px; margin: 0 auto; background:#161a23; border-radius: 10px;
          padding: 32px; border:1px solid #232838; }
  h1 { margin: 0 0 12px; font-size: 32px; }
  p  { color:#c8c8c8; line-height: 1.6; }
  .openbtn { display:inline-block; background:#3da25f; color:#fff;
             padding: 12px 22px; border-radius: 4px; text-decoration:none;
             font-weight:700; font-size:15px; margin-top: 18px; }
  .openbtn:hover { background:#48b96d; }
  code { background:#0b1020; padding:2px 6px; border-radius:4px; color:#9ce39c; }
  ul { color:#c8c8c8; line-height:1.7; }
</style></head>
<body><div class="card">
  <h1>PROOF Network — verification demo</h1>
  <p>Click the button below. You will be sent through the same kind of
     interstitial Cloudflare uses (<em>"Performing security verification"</em>),
     except every signal it evaluates is real:</p>
  <ul>
    <li>A SHA-256 proof-of-work, sized to the visitor's risk score</li>
    <li>27 browser-environment integrity features (canvas, WebGL, audio,
        WebRTC IP, automation surfaces, font enumeration…)</li>
    <li>An IsolationForest anomaly model trained on a real human population</li>
    <li>A weighted risk engine that returns a Cloudflare four-path verdict
        (<code>ALLOW / ALLOW_WITH_INTERACTION / CHALLENGE / BLOCK</code>)</li>
  </ul>
  <p>On success you will be redirected to the protected page with a one-time
     response token, which the relying-party backend consumes via
     <code>POST /api/siteverify</code>.</p>
  __OPEN_BUTTON__
  <p style="margin-top:24px;font-size:13px;color:#9aa1a6;">
     No demo site is registered yet. Open the Streamlit admin (port 5000),
     go to <em>7. Sites</em>, register one, then refresh this page.</p>
</div></body></html>"""


def _render(template: str, **subs: str) -> str:
    out = template
    for k, v in subs.items():
        out = out.replace(f"__{k}__", v)
    return out


_DEMO_SITE_LABEL = "PROOF Demo (interstitial)"
_DEMO_SITE_DOMAIN = "demo.proof.local"


def build_app(protocol: ProofProtocol) -> FastAPI:
    app = FastAPI(title="PROOF Network — Public API", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )

    def _demo_site():
        """Return (or lazily create) the site used by the built-in /protected
        demo. Keeps the demo self-contained so visiting /protected after a
        fresh start still works."""
        for s in protocol.sites.list():
            if s.label == _DEMO_SITE_LABEL:
                return s
        return protocol.sites.register(
            label=_DEMO_SITE_LABEL,
            domain=_DEMO_SITE_DOMAIN,
            min_action="ALLOW",
        )

    def _hostname_from_request(request: Request) -> str:
        host = request.headers.get("host", "demo.proof.local")
        return host.split(":")[0]

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "stats": protocol.stats(), "ts": time.time()}

    # ----- Cloudflare-style interstitial (real, not a mockup) ----------- #

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> str:
        site = _demo_site()
        # Build the "Open" button → /protected on this same server. /protected
        # will see no token and redirect into /verify, which will run the real
        # PROOF verification, then redirect back with a one-time response token.
        proto_scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("host", str(request.base_url).split("://")[-1].rstrip("/"))
        protected_url = f"{proto_scheme}://{host}/protected"
        button = f'<a class="openbtn" href="{html.escape(protected_url)}">Open</a>'
        return _render(_HOME_HTML, OPEN_BUTTON=button)

    @app.get("/verify", response_class=HTMLResponse)
    def verify_page(
        request: Request,
        sitekey: str = Query(""),
        destination: str = Query("/protected"),
    ) -> str:
        site = protocol.sites.get(sitekey) if sitekey else _demo_site()
        if not site or not site.active:
            site = _demo_site()
        # Constrain destination to a same-origin path so /verify can't be
        # weaponised into an open redirector.
        parsed = urlparse(destination)
        if parsed.scheme or parsed.netloc:
            destination = "/protected"
        ray_id = "PR-" + secrets.token_hex(10)
        # Use the request's own base URL so the widget calls the same origin
        # the visitor reached us on (works through the Replit dev proxy too).
        api_base = str(request.base_url).rstrip("/")
        hostname = _hostname_from_request(request)
        return _render(
            _INTERSTITIAL_HTML,
            HOSTNAME=html.escape(hostname),
            RAY_ID=html.escape(ray_id),
            API=html.escape(api_base),
            SITEKEY_JSON=json.dumps(site.site_key),
            DEST_JSON=json.dumps(destination),
            RAY_JSON=json.dumps(ray_id),
        )

    @app.get("/protected", response_class=HTMLResponse)
    def protected_page(
        request: Request,
        proof_token: str = Query(""),
        proof_sitekey: str = Query(""),
        proof_ray: str = Query(""),
    ) -> Any:
        # Step 1: no token → redirect into the verification interstitial.
        if not proof_token:
            site = _demo_site()
            return RedirectResponse(
                url=f"/verify?sitekey={site.site_key}&destination=/protected",
                status_code=302,
            )

        # Step 2: validate the token. consume_response_token is one-time, so
        # this proves the visitor actually went through the interstitial.
        site_key = proof_sitekey or _demo_site().site_key
        verdict = protocol.consume_response_token(
            response_token=proof_token, site_key=site_key
        )
        hostname = _hostname_from_request(request)
        if not verdict or not verdict.get("success"):
            reason = (
                "Token already used or expired"
                if verdict is None
                else f"Token rejected: action={verdict.get('action')}"
            )
            return HTMLResponse(
                _render(
                    _PROTECTED_FAIL_HTML,
                    REASON=html.escape(reason),
                    VERIFY_URL=f"/verify?sitekey={site_key}&destination=/protected",
                ),
                status_code=403,
            )

        return _render(
            _PROTECTED_OK_HTML,
            HOSTNAME=html.escape(hostname),
            ACTION=html.escape(str(verdict.get("action", ""))),
            SCORE=f"{float(verdict.get('score', 0.0)):.1f}",
            FP=html.escape(str(verdict.get("fingerprint", ""))),
            TOKEN=html.escape(proof_token[:32] + "…"),
            RAY=html.escape(proof_ray or "(none)"),
            TS=html.escape(time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                         time.gmtime(float(verdict.get("ts", time.time()))))),
        )

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
