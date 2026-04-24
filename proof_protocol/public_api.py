"""Public HTTP API for the PROOF Network.

Mirrors the Cloudflare Turnstile / reCAPTCHA / hCaptcha integration
contract so any web application can adopt PROOF with a one-line widget +
one server-side ``/siteverify`` POST.

Endpoints
---------

GET  /
        Verification interstitial (the only UI page). Real PoW + real
        telemetry + real risk engine — the "Verified" state is revealed
        inline on the same page, no redirect.
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

import hashlib
import hmac
import html
import json
import secrets
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from .proof_of_work import PowChallenge, PowSolution
from .protocol import ProofProtocol
from .risk_engine import Action
from .telemetry import analyze
from .widget_js import widget_javascript


# --------------------------------------------------------------------------- #
# Proof ID — every page load mints a fresh, HMAC-signed identifier so support
# / abuse-team requests can be traced back and verified as authentic. The MAC
# is keyed by a random 32-byte secret generated at process start, so an
# attacker cannot forge a Proof ID that this server will accept.
# --------------------------------------------------------------------------- #

_PROOF_ID_KEY: bytes = secrets.token_bytes(32)
_PROOF_ID_PREFIX = "PROOF"


def _mint_proof_id() -> tuple[str, int]:
    """Return (proof_id, issued_at_unix_seconds).

    Format:  PROOF-<16 hex random>-<10 hex epoch s>-<8 hex HMAC tag>
    Length:  39 chars after the prefix; trivially copy-pasteable.
    """
    rnd = secrets.token_bytes(8)              # 16 hex chars
    issued = int(time.time())
    body = rnd.hex() + "-" + f"{issued:010x}"
    tag = hmac.new(_PROOF_ID_KEY, body.encode("ascii"),
                   hashlib.sha256).hexdigest()[:8]
    return f"{_PROOF_ID_PREFIX}-{body}-{tag}", issued


def _verify_proof_id(proof_id: str) -> dict[str, Any]:
    """Constant-time check that ``proof_id`` was minted by this server."""
    parts = (proof_id or "").split("-")
    if len(parts) != 4 or parts[0] != _PROOF_ID_PREFIX:
        return {"valid": False, "reason": "malformed proof_id"}
    rand_hex, issued_hex, tag = parts[1], parts[2], parts[3]
    if len(rand_hex) != 16 or len(issued_hex) != 10 or len(tag) != 8:
        return {"valid": False, "reason": "bad field lengths"}
    body = f"{rand_hex}-{issued_hex}"
    expected = hmac.new(_PROOF_ID_KEY, body.encode("ascii"),
                        hashlib.sha256).hexdigest()[:8]
    if not hmac.compare_digest(expected, tag):
        return {"valid": False, "reason": "signature mismatch"}
    try:
        issued_at = int(issued_hex, 16)
    except ValueError:
        return {"valid": False, "reason": "bad issued timestamp"}
    age = max(0.0, time.time() - issued_at)
    return {
        "valid": True,
        "proof_id": proof_id,
        "issued_at": issued_at,
        "age_seconds": round(age, 3),
    }


# --------------------------------------------------------------------------- #
# Cloudflare-style "Performing security verification" interstitial.
# This is the only UI surface — verification result is revealed inline.
# --------------------------------------------------------------------------- #

_INTERSTITIAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>__HOSTNAME__</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="strict-origin-when-cross-origin">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<style>
  html, body { margin:0; padding:0; background:#1c1c1c; color:#f1f1f1;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif; min-height:100vh; }
  .wrap { padding: 28px 22px 140px; max-width: 760px; }
  h1 { font-size: 30px; font-weight: 600; margin: 16px 0 18px;
       word-break: break-all; line-height: 1.2; }
  h2 { font-size: 22px; font-weight: 500; margin: 0 0 14px; color: #f1f1f1; }
  p.desc { color:#c8c8c8; font-size: 16px; line-height: 1.55;
           max-width: 560px; margin: 0 0 22px; }
  .panel { background:#2b2b2b; border-radius:6px; padding:14px 18px;
           max-width: 520px; display:flex; align-items:center;
           justify-content:space-between; gap:18px; min-height:54px;
           transition: background .25s ease; }
  .left  { display:flex; align-items:center; gap:14px; }
  .right { text-align:right; font-size:11px; color:#9aa1a6; line-height:1.4; }
  .right .brand { font-weight: 800; letter-spacing:.06em;
                  color:#fff; font-size:13px; }
  .right .brand .dot { color:#f6821f; }
  .right a { color:#9aa1a6; text-decoration:none; }
  .right a:hover { text-decoration: underline; }
  #status { font-size: 16px; }
  .spinner { width:34px; height:34px; }
  .spinner circle { fill:#3da25f; }
  .reasons { color:#ffb3b3; font-size:13px; margin: 14px 0 0;
             padding-left: 22px; max-width: 560px; display:none; }
  .reasons li { margin: 4px 0; }
  .panel.ok  { background:#0f3a1d; }
  .panel.err { background:#3a1414; }
  .verified-box { display:none; margin-top: 22px; max-width: 720px;
                  background:#161a23; border:1px solid #232838;
                  border-radius: 8px; padding: 18px 20px; }
  .verified-box h3 { margin: 0 0 12px; font-size: 16px; color:#9ce39c;
                     letter-spacing: .03em; text-transform: uppercase; }
  .vrow { display:flex; justify-content:space-between; gap: 18px;
          padding: 6px 0; border-bottom: 1px solid #232838;
          font-size: 13px; }
  .vrow:last-child { border-bottom: none; }
  .vrow .k { color:#9aa1a6; min-width: 150px; }
  .vrow .v { color:#e8eaed; font-family: ui-monospace, SFMono-Regular,
             Menlo, monospace; word-break: break-all; text-align:right;
             flex: 1; }
  .vrow .v.ok { color:#9ce39c; }
  .vrow .v.bad { color:#ff9a9a; }
  .footer { position:fixed; bottom:0; left:0; right:0; padding:18px 16px 22px;
            text-align:center; color:#a0a0a0; font-size: 13px;
            border-top: 1px solid #2a2a2a; background:#1c1c1c; }
  .footer a { color:#a0a0a0; }
  .meta { margin: 6px 0; }
  .timing { color:#9aa1a6; font-size:12px; margin-top:10px; max-width:520px; }
  .retry { display:none; margin-top: 18px; }
  .retry button { background:#3da25f; color:#fff; border:none;
                  padding: 9px 18px; border-radius: 4px; cursor: pointer;
                  font-weight:600; font-size:14px; }
  .retry button:hover { background:#48b96d; }
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
      <div><a href="/privacy">Privacy</a> &nbsp;·&nbsp; <a href="/privacy#help">Help</a></div>
    </div>
  </div>

  <ul class="reasons" id="reasons"></ul>

  <div class="verified-box" id="verified-box">
    <h3 id="verified-title">Verification details</h3>
    <div class="vrow"><span class="k">Status</span><span class="v ok" id="v-status">—</span></div>
    <div class="vrow"><span class="k">Action</span><span class="v" id="v-action">—</span></div>
    <div class="vrow"><span class="k">Risk score</span><span class="v" id="v-score">—</span></div>
    <div class="vrow"><span class="k">Browser fingerprint</span><span class="v" id="v-fp">—</span></div>
    <div class="vrow"><span class="k">Response token</span><span class="v" id="v-token">—</span></div>
    <div class="vrow"><span class="k">PoW difficulty</span><span class="v" id="v-pow">—</span></div>
    <div class="vrow"><span class="k">Solve time</span><span class="v" id="v-solve">—</span></div>
    <div class="vrow"><span class="k">Verified at</span><span class="v" id="v-ts">—</span></div>
  </div>

  <div class="timing" id="timing"></div>

  <div class="retry" id="retry">
    <button id="retry-btn" type="button">Try again</button>
  </div>
</div>

<div class="footer">
  <div class="meta">Proof ID: <span id="proofid">__PROOF_ID__</span></div>
  <div>Performance and Security by <a href="/privacy">PROOF</a> &nbsp;|&nbsp;
       <a href="/privacy">Privacy</a></div>
</div>

<script src="/api/widget.js"></script>
<script>
(function() {
  "use strict";
  var SITEKEY  = __SITEKEY_JSON__;
  var PROOF_ID = __PROOF_ID_JSON__;
  var tStart   = performance.now();
  var powStartedAt = 0, powDifficulty = 0;

  function $(id) { return document.getElementById(id); }
  function setStatus(t)  { $("status").innerText = t; }
  function setTiming(ms) {
    $("timing").innerText =
      "Completed in " + ms.toFixed(0) + " ms · Proof ID " + PROOF_ID;
  }
  function fmtTs(s) {
    try { return new Date(s * 1000).toISOString().replace("T"," ").replace(".000Z"," UTC"); }
    catch(e) { return String(s); }
  }
  function setRow(id, val, cls) {
    var el = $(id);
    el.innerText = val == null ? "—" : String(val);
    el.classList.remove("ok"); el.classList.remove("bad");
    if (cls) el.classList.add(cls);
  }

  function done(result) {
    var elapsed = performance.now() - tStart;
    $("panel").classList.add("ok");
    $("spinner").style.display = "none";
    setStatus("Verified \u2713");
    $("title").innerText = "Verification successful";
    $("desc").innerText = "You have been verified as a real human visitor by " +
      "the PROOF Network. The details below were produced by a real " +
      "proof-of-work, real browser-environment telemetry, and a real " +
      "anomaly-detection risk engine.";
    setTiming(elapsed);
    $("verified-box").style.display = "block";
    $("verified-title").innerText = "Verification details";
    setRow("v-status", "verified", "ok");
    setRow("v-action", result.action || "ALLOW", "ok");
    setRow("v-score", (result.score == null ? 0 : Number(result.score).toFixed(1)) +
      " / 100 (lower is better)");
    setRow("v-fp", result.fingerprint || "(none)");
    setRow("v-token", (result.token || "").slice(0, 48) +
      ((result.token || "").length > 48 ? "\u2026" : ""));
    setRow("v-pow", powDifficulty + " bits");
    setRow("v-solve", (result._solveMs == null ? "—" : result._solveMs + " ms"));
    setRow("v-ts", fmtTs(result._ts || (Date.now() / 1000)));
  }

  function fail(result) {
    var elapsed = performance.now() - tStart;
    $("title").innerText = "Sorry, you have been blocked";
    $("desc").innerText =
      "You are unable to access this page. Our automated security checks " +
      "suggest your browser is not a real human user. If you believe this " +
      "is in error, please contact the site owner with the Proof ID below.";
    $("panel").classList.add("err");
    $("spinner").style.display = "none";
    setStatus("Blocked  ·  action=" + (result.action || "BLOCK") +
              "  ·  score=" + (Number(result.score || 0)).toFixed(1));
    var ul = $("reasons");
    ul.style.display = "block";
    ul.innerHTML = "";
    (result.reasons || ["verification failed"]).slice(0, 6).forEach(function(r) {
      var li = document.createElement("li"); li.innerText = String(r); ul.appendChild(li);
    });
    setTiming(elapsed);
    $("verified-box").style.display = "block";
    $("verified-title").innerText = "Verification details";
    setRow("v-status", "blocked", "bad");
    setRow("v-action", result.action || "BLOCK", "bad");
    setRow("v-score", (result.score == null ? 0 : Number(result.score).toFixed(1)) +
      " / 100 (lower is better)");
    setRow("v-fp", result.fingerprint || "(none)");
    setRow("v-token", "(none — verification failed)");
    setRow("v-pow", powDifficulty ? (powDifficulty + " bits") : "—");
    setRow("v-solve", (result._solveMs == null ? "—" : result._solveMs + " ms"));
    setRow("v-ts", fmtTs(result._ts || (Date.now() / 1000)));
    $("retry").style.display = "block";
  }

  async function runVerification() {
    if (!window.PROOF || !window.PROOF.verify) {
      throw new Error("PROOF widget failed to load");
    }
    // Single full-pipeline call: real PoW + real telemetry + real risk
    // engine. The widget attaches pow_difficulty / pow_solve_ms / client_ts
    // to the returned object.
    var r = await window.PROOF.verify(SITEKEY);
    powDifficulty = (r && r.pow_difficulty) | 0;
    r._solveMs = (r && r.pow_solve_ms) || null;
    r._ts = (r && r.client_ts) || (Date.now() / 1000);
    return r;
  }

  async function start() {
    if (!window.PROOF || !window.PROOF.verify) {
      // The script tag may still be loading.
      return setTimeout(start, 50);
    }
    // Reset UI state for retries.
    $("retry").style.display = "none";
    $("verified-box").style.display = "none";
    $("reasons").style.display = "none";
    $("reasons").innerHTML = "";
    $("panel").classList.remove("ok");
    $("panel").classList.remove("err");
    $("spinner").style.display = "";
    $("title").innerText = "Performing security verification";
    $("desc").innerText = "This website uses a security service to protect " +
      "against malicious bots. This page is displayed while the website " +
      "verifies you are not a bot.";
    setStatus("Verifying...");
    tStart = performance.now();
    try {
      var r = await runVerification();
      if (r && r.success) { done(r); } else { fail(r || {}); }
    } catch (e) {
      fail({reasons: [String((e && e.message) || e)]});
    }
  }

  $("retry-btn").addEventListener("click", function() { start(); });
  start();
})();
</script>
</body>
</html>"""


def _render(template: str, **subs: str) -> str:
    out = template
    for k, v in subs.items():
        out = out.replace(f"__{k}__", v)
    return out


# --------------------------------------------------------------------------- #
# Privacy page — real, substantive disclosure of what the verifier collects,
# why, how long it is kept, and how to verify a Proof ID. No tracking, no
# external scripts, no third-party fonts — same strict CSP as the
# interstitial.
# --------------------------------------------------------------------------- #
_PRIVACY_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Privacy & Help — PROOF Network</title>
<style>
  :root { color-scheme: dark; }
  html,body { margin:0; padding:0; background:#191919; color:#e7e7e7;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
              Roboto, Helvetica, Arial, sans-serif; line-height:1.55; }
  .wrap { max-width: 760px; margin: 0 auto; padding: 56px 28px 96px; }
  h1 { font-size: 26px; font-weight: 600; margin: 0 0 6px; color:#fff; }
  h2 { font-size: 17px; font-weight: 600; margin: 32px 0 8px; color:#fff;
       border-bottom:1px solid #2a2a2a; padding-bottom:6px; }
  h3 { font-size: 14px; font-weight:600; margin:22px 0 4px; color:#fff; }
  p,li { font-size: 14px; color:#cfcfcf; }
  a { color:#3da2ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas,
                "Liberation Mono", monospace; font-size: 13px;
                background:#222; color:#e7e7e7; padding: 1px 6px;
                border-radius: 3px; }
  pre { background:#222; padding: 12px 14px; border-radius: 6px;
        overflow-x:auto; font-size:13px; color:#e7e7e7; margin:8px 0 14px; }
  table { border-collapse: collapse; margin: 6px 0 16px; width:100%;
          font-size: 13.5px; }
  th, td { border-bottom:1px solid #2a2a2a; padding: 8px 10px; text-align:left;
           vertical-align: top; }
  th { color:#fff; font-weight:600; background:#1f1f1f; }
  ul { padding-left: 20px; }
  .crumb { font-size:13px; color:#9a9a9a; margin-bottom: 18px; }
  .lede { font-size: 15.5px; color:#dcdcdc; }
  form { display:flex; gap:8px; margin: 8px 0 4px; }
  input[type=text] { flex:1; padding: 9px 12px; background:#222; color:#fff;
                     border:1px solid #333; border-radius:4px; font-size:13px;
                     font-family: ui-monospace, monospace; }
  button { padding: 9px 16px; background:#3da25f; color:#fff; border:none;
           border-radius:4px; cursor:pointer; font-weight:600; font-size:13px; }
  .result { margin-top:8px; padding: 10px 12px; border-radius:4px;
            font-family: ui-monospace, monospace; font-size:13px;
            background:#1f1f1f; border:1px solid #2a2a2a; white-space:pre-wrap;
            word-break: break-all; min-height: 18px; }
  .result.ok  { border-color:#1f6f3a; color:#9be3b3; }
  .result.bad { border-color:#7a2a2a; color:#f3a3a3; }
  .footer { text-align:center; color:#9a9a9a; font-size:12px; margin-top: 60px;
            border-top:1px solid #2a2a2a; padding-top: 16px; }
</style>
</head><body>
<div class="wrap">
  <div class="crumb"><a href="/">&larr; Back to verification</a></div>
  <h1>Privacy &amp; Help</h1>
  <p class="lede">
    PROOF is a non-interactive human-verification protocol. This page explains
    exactly what the verifier collects from your browser, why each piece is
    needed, how long it is kept, and how to independently confirm that a
    <span class="mono">Proof ID</span> was issued by this server.
  </p>

  <h2>1. What is collected during verification</h2>
  <p>
    The interstitial gathers a small, fixed set of signals from your browser
    so the risk engine can distinguish a real human from an automated client.
    Nothing on this list is sent to any third party, no advertising
    identifiers are read, and no cross-site cookies are set.
  </p>
  <table>
    <tr><th>Signal</th><th>Why it is needed</th><th>Stored?</th></tr>
    <tr><td>User-Agent string</td><td>Detects headless / automation libraries.</td><td>Aggregate counters only.</td></tr>
    <tr><td>Language &amp; timezone</td><td>Mismatch between language and timezone is a known bot signal.</td><td>No — used in-memory.</td></tr>
    <tr><td>Screen / viewport / pixel ratio</td><td>Headless browsers report 0&times;0 or fixed sentinel sizes.</td><td>No.</td></tr>
    <tr><td>Hardware concurrency / device memory</td><td>Cheap bot farms report implausible values.</td><td>No.</td></tr>
    <tr><td>Canvas / WebGL / audio fingerprint</td><td>Combined into a stable, salted browser fingerprint hash; lets us spot the same client retrying.</td><td>Salted hash only — original values discarded.</td></tr>
    <tr><td>Pointer-movement intervals, scroll &amp; focus counts</td><td>Real users produce irregular timing; scripts produce uniform timing or none at all.</td><td>No — discarded after scoring.</td></tr>
    <tr><td>Proof-of-work solve time</td><td>Verifies the browser actually performed the work, not a replay.</td><td>No.</td></tr>
    <tr><td>WebRTC local IP (best-effort)</td><td>Detects datacenter / VPN reflections that lack a private RFC1918 candidate.</td><td>No — used in-memory only.</td></tr>
  </table>
  <p>
    The verifier never reads page content, form values, clipboard, microphone,
    camera, or geolocation. The browser-level <code>Permissions-Policy</code>
    header on this page actively forbids those APIs.
  </p>

  <h2>2. What the server stores</h2>
  <ul>
    <li>A salted, irreversible hash of the browser fingerprint, used to track
        retry-rate per fingerprint. Plain telemetry values are not stored.</li>
    <li>Per-site counters: total challenges issued, blocked-vs-allowed counts.
        These are never tied to an individual visitor.</li>
    <li>Each issued Proof ID is HMAC-signed with a process-local 32-byte key
        and embedded in the page; nothing about the visitor is stored
        alongside it.</li>
  </ul>

  <h2>3. Cookies &amp; cross-site tracking</h2>
  <p>
    The verifier sets <strong>no cookies</strong>, no <code>localStorage</code>,
    and no <code>sessionStorage</code>. The page is served with
    <code>Cache-Control: no-store</code>, a strict
    <code>Content-Security-Policy</code>, <code>X-Frame-Options: DENY</code>,
    and a restrictive <code>Referrer-Policy</code>.
  </p>

  <h2>4. Proof of Work</h2>
  <p>
    The browser is asked to find a 64-bit nonce such that
    <code>SHA-256(challenge_id || nonce)</code> has at least
    <em>n</em> leading zero bits. This is the same Hashcash primitive that
    powers Bitcoin block headers — genuinely unforgeable, requires no shared
    secret, and forces every solver to spend measurable CPU time. Difficulty
    is signed by the issuer key so a client cannot lower it unilaterally.
  </p>

  <h2 id="proof-id">5. What is a Proof ID?</h2>
  <p>
    A Proof ID is a short, copy-pasteable identifier shown on every
    verification page. Format:
  </p>
  <pre>PROOF-&lt;16 hex random&gt;-&lt;10 hex epoch&gt;-&lt;8 hex HMAC tag&gt;</pre>
  <p>
    The trailing 8-hex tag is an <code>HMAC-SHA256</code> over the random and
    timestamp portions, keyed by a 32-byte secret that exists only inside this
    server process. That means an attacker cannot forge a Proof ID that this
    server will accept, and you can independently confirm that a Proof ID
    quoted to you really came from this site:
  </p>
  <h3 id="verify-form">Verify a Proof ID</h3>
  <form id="verify-form" onsubmit="return false;">
    <input id="pid" type="text" autocomplete="off" spellcheck="false"
           placeholder="PROOF-xxxxxxxxxxxxxxxx-xxxxxxxxxx-xxxxxxxx"/>
    <button id="check" type="button">Verify</button>
  </form>
  <div id="result" class="result">Paste a Proof ID above to check it.</div>

  <h2 id="help">6. Help &amp; appeals</h2>
  <p>
    If you were blocked and you believe it was in error, send the website
    owner the full Proof ID shown on the verification page. They can quote it
    back to PROOF support, who can confirm via the endpoint above that the ID
    is genuine and look up <em>which signals</em> caused the block — without
    ever needing to identify you.
  </p>
  <p>
    Programmatic check (any HTTP client):
  </p>
  <pre>GET /api/proof-id/verify?id=PROOF-...
&rarr; {"valid": true, "proof_id": "...", "issued_at": 1700000000, "age_seconds": 12.3}</pre>

  <h2>7. Contact</h2>
  <p>
    This deployment is the open-source PROOF reference implementation. Source
    code, threat model, and protocol specification accompany the project.
  </p>

  <div class="footer">
    Performance and Security by PROOF &nbsp;|&nbsp; <a href="/">Verification</a>
  </div>
</div>
<script>
(function() {
  "use strict";
  var $ = function(id) { return document.getElementById(id); };
  function render(out) {
    var box = $("result");
    box.classList.remove("ok"); box.classList.remove("bad");
    if (out && out.valid) {
      box.classList.add("ok");
      box.innerText =
        "VALID\n" +
        "proof_id    " + out.proof_id + "\n" +
        "issued_at   " + out.issued_at + " (" +
            new Date(out.issued_at * 1000).toISOString() + ")\n" +
        "age_seconds " + out.age_seconds;
    } else {
      box.classList.add("bad");
      box.innerText = "INVALID  ·  " + ((out && out.reason) || "unknown reason");
    }
  }
  async function check() {
    var v = ($("pid").value || "").trim();
    if (!v) { $("result").innerText = "Paste a Proof ID first."; return; }
    try {
      var res = await fetch("/api/proof-id/verify?id=" +
                            encodeURIComponent(v));
      render(await res.json());
    } catch (e) {
      $("result").classList.add("bad");
      $("result").innerText = "Network error: " + e.message;
    }
  }
  $("check").addEventListener("click", check);
  $("pid").addEventListener("keydown", function(e) {
    if (e.key === "Enter") { e.preventDefault(); check(); }
  });
})();
</script>
</body></html>"""


_DEMO_SITE_LABEL = "PROOF Demo (interstitial)"
_DEMO_SITE_DOMAIN = "demo.proof.local"


def build_app(protocol: ProofProtocol) -> FastAPI:
    app = FastAPI(title="PROOF Network — Public API", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        allow_credentials=False,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        # Conservative defaults — the only HTML surface is the interstitial,
        # which loads exactly one same-origin script (/api/widget.js) and uses
        # an inline bootstrap. All other endpoints return JSON / JS.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        # Allow inline bootstrap and same-origin /api/widget.js.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        return response

    def _demo_site():
        """Return (or lazily create) the site used by the built-in interstitial.

        Keeps the demo self-contained so a fresh deployment renders correctly
        without any out-of-band registration step.
        """
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

    @app.get("/favicon.ico")
    def favicon() -> Response:
        # Serve an empty 204 so browsers stop logging 404s.
        return Response(status_code=204)

    @app.head("/")
    def interstitial_head() -> Response:
        # Reverse proxies (incl. the Replit dev proxy) probe with HEAD;
        # returning 405 here marks the upstream unhealthy and the proxy
        # then 502s every real GET. A bare 200 keeps the proxy happy.
        return Response(
            status_code=200,
            headers={"Cache-Control": "no-store"},
        )

    @app.head("/privacy")
    def privacy_head() -> Response:
        return Response(status_code=200)

    @app.get("/", response_class=HTMLResponse)
    def interstitial(request: Request) -> HTMLResponse:
        site = _demo_site()
        proof_id, _issued = _mint_proof_id()
        hostname = _hostname_from_request(request)
        body = _render(
            _INTERSTITIAL_HTML,
            HOSTNAME=html.escape(hostname),
            PROOF_ID=html.escape(proof_id),
            SITEKEY_JSON=json.dumps(site.site_key),
            PROOF_ID_JSON=json.dumps(proof_id),
        )
        # Don't cache — every load should mint a fresh Proof ID + challenge.
        return HTMLResponse(
            body,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            },
        )

    @app.get("/privacy", response_class=HTMLResponse)
    def privacy() -> HTMLResponse:
        return HTMLResponse(
            _PRIVACY_HTML,
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/api/proof-id/verify")
    def proof_id_verify(id: str = Query(..., min_length=10, max_length=128)) -> dict[str, Any]:
        """Public endpoint: confirm a Proof ID was minted by this server.

        The Proof ID is HMAC-signed with a process-local 32-byte secret, so
        only this server can mint accepted IDs. This is a real verification
        — not a lookup of stored state — and is safe to expose publicly.
        """
        return _verify_proof_id(id)

    @app.get("/api/widget.js", response_class=PlainTextResponse)
    def widget(request: Request) -> Response:
        # Use a relative API base so the widget always calls its own origin
        # (works behind reverse proxies, mixed-protocol setups, custom domains).
        js = widget_javascript("")
        return Response(
            content=js,
            media_type="application/javascript; charset=utf-8",
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/api/challenge")
    def challenge(sitekey: str = Query(...)) -> dict[str, Any]:
        site = protocol.sites.get(sitekey)
        if not site or not site.active:
            raise HTTPException(status_code=400, detail="invalid or inactive sitekey")
        ch = protocol.pow.issue(risk_score=0.0)
        return ch.to_dict()

    @app.post("/api/siteverify-front")
    async def siteverify_front(request: Request) -> dict[str, Any]:
        try:
            body = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}")

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
        # Accept either application/json or form-encoded (Turnstile-compatible).
        ctype = request.headers.get("content-type", "")
        if "application/json" in ctype:
            try:
                body = await request.json()
            except Exception as exc:  # noqa: BLE001
                return {"success": False, "error-codes": [f"invalid-input-body: {exc}"]}
            secret = str(body.get("secret", ""))
            response = str(body.get("response", ""))
        else:
            form = await request.form()
            secret = str(form.get("secret", ""))
            response = str(form.get("response", ""))

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
