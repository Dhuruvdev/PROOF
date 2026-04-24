"""PROOF — The UPI of Human Verification.

A pure-Python Streamlit application that demonstrates the full PROOF
Protocol end-to-end with real cryptography:

* secp256k1 ECC, Pedersen commitments, Schnorr ZK proofs
* AES-256-GCM device-bound secure enclave
* Behavioral feature extraction (keystroke dynamics + tremor band power)
* Open validator network with 2/3 quorum
* Trust-tier marketplace (BASIC / STANDARD / PREMIUM)
* Revocation, reputation, and an end-to-end audit log
"""

from __future__ import annotations

import json
import platform
import time
import uuid
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

import os

from proof_protocol.behavioral_dna import (
    FEATURE_NAMES,
    MATCH_THRESHOLD,
    cosine_distance,
    extract_features,
)
from proof_protocol.protocol import ProofProtocol, ProofToken, Tier
from proof_protocol.risk_engine import Action
from proof_protocol.trust_tiers import POLICIES


def _api_base() -> str:
    """The public URL where the FastAPI server is reachable.

    On Replit, port 8000 is exposed externally at ``https://<dev-domain>:8000/``
    (configured via ``[[ports]]`` in ``.replit``). When this app is shown to
    a user via the preview pane we must hand them that public URL — the
    ``localhost`` fallback only works inside the workspace container.
    """
    explicit = os.environ.get("PROOF_API_BASE")
    if explicit:
        return explicit.rstrip("/")
    domain = os.environ.get("REPLIT_DEV_DOMAIN")
    if domain:
        return f"https://{domain}:8000"
    return "http://localhost:8000"


# --------------------------------------------------------------------------- #
# Bootstrapping
# --------------------------------------------------------------------------- #


DATA_DIR = Path("data")


@st.cache_resource
def get_protocol() -> ProofProtocol:
    proto = ProofProtocol(DATA_DIR)
    # Seed an initial validator quorum if none exists yet so the network is
    # immediately usable. Operators can be added/removed from the UI.
    if not proto.network.active_validators():
        for op, region in [
            ("NPCI", "ap-south-1"),
            ("Aadhaar-CIDR", "ap-south-1"),
            ("Government-of-India", "ap-south-1"),
            ("Reliance-Jio", "ap-south-1"),
            ("Tata-Comms", "ap-south-1"),
        ]:
            proto.network.add_validator(op, region)
    return proto


def init_state() -> None:
    ss = st.session_state
    ss.setdefault("device_id", None)
    ss.setdefault("passphrase", "")
    ss.setdefault("machine_signals", {
        "ua": platform.platform(),
        "py": platform.python_version(),
        "session_uuid": uuid.uuid4().hex,  # one synthetic device per browser session
    })
    ss.setdefault("issued_token", None)
    ss.setdefault("issued_token_json", "")
    ss.setdefault("last_distance", None)
    ss.setdefault("last_live_features", None)
    ss.setdefault("last_quorum", None)
    ss.setdefault("last_match_table", None)


# --------------------------------------------------------------------------- #
# Keystroke capture (browser-side JS posts events back into Streamlit)
# --------------------------------------------------------------------------- #


CAPTURE_HTML = """
<div id="capture-root" style="font-family: system-ui, -apple-system, sans-serif;">
  <p style="margin: 0 0 6px 0; color:#444; font-size: 14px;">
    Type the phrase below at your natural speed (do <b>not</b> paste).
    The widget records keystroke timings (millisecond precision via
    <code>performance.now()</code>). When done, click
    <b>Export JSON</b> and copy the result into the text area below.
  </p>
  <p style="margin: 0 0 6px 0; padding: 6px 10px; background:#f5f5f5;
            border-radius: 6px; font-size: 14px;">{phrase}</p>
  <textarea id="kb-area" rows="2" style="width:100%; padding:8px;
            font-size: 14px; border-radius:6px; border:1px solid #ccc;"
            placeholder="Start typing here..."></textarea>
  <div style="display:flex; gap:8px; align-items:center; margin: 8px 0;">
    <button id="kb-export"
            style="padding:6px 14px; background:#0066ff; color:white;
                   border:none; border-radius:6px; cursor:pointer;">
      Export JSON
    </button>
    <button id="kb-copy"
            style="padding:6px 14px; background:#16a34a; color:white;
                   border:none; border-radius:6px; cursor:pointer;">
      Copy to clipboard
    </button>
    <button id="kb-clear"
            style="padding:6px 14px; background:#eee; color:#333;
                   border:1px solid #ccc; border-radius:6px; cursor:pointer;">
      Clear
    </button>
    <span id="kb-stats" style="color:#666; font-size: 13px;"></span>
  </div>
  <textarea id="kb-out" rows="4" readonly
            style="width:100%; padding:8px; font-size: 12px;
                   font-family: ui-monospace, monospace;
                   border-radius:6px; border:1px solid #ccc;
                   background:#fafafa;"
            placeholder="Captured JSON will appear here..."></textarea>
</div>
<script>
(function() {{
  const area = document.getElementById('kb-area');
  const out = document.getElementById('kb-out');
  const exportBtn = document.getElementById('kb-export');
  const copyBtn = document.getElementById('kb-copy');
  const clear = document.getElementById('kb-clear');
  const stats = document.getElementById('kb-stats');
  let events = [];
  let downMap = {{}};

  function now() {{ return performance.now() / 1000.0; }}
  function update() {{
    stats.innerText = events.length + ' keys captured';
  }}

  area.addEventListener('keydown', (e) => {{
    if (e.key.length !== 1 && e.key !== 'Backspace' && e.key !== ' ') return;
    if (downMap[e.key] === undefined) {{ downMap[e.key] = now(); }}
  }});
  area.addEventListener('keyup', (e) => {{
    const d = downMap[e.key];
    if (d !== undefined) {{
      events.push({{key: e.key, down: d, up: now()}});
      delete downMap[e.key];
      update();
    }}
  }});
  clear.addEventListener('click', () => {{
    events = []; downMap = {{}}; area.value = ''; out.value = ''; update();
  }});
  exportBtn.addEventListener('click', () => {{
    out.value = JSON.stringify(events);
    out.select();
  }});
  copyBtn.addEventListener('click', () => {{
    out.value = JSON.stringify(events);
    out.select();
    try {{ navigator.clipboard.writeText(out.value); }} catch (e) {{}}
    document.execCommand && document.execCommand('copy');
    stats.innerText = 'copied ' + events.length + ' events to clipboard';
  }});
}})();
</script>
"""


def keystroke_collector(phrase: str, state_key: str) -> list[dict] | None:
    """Live JS capture widget + Python-side intake.

    The browser widget records real keystroke timings, then the user
    pastes the JSON into the visible text area or clicks the synthetic
    capture button (useful when running headless).
    """
    components.html(
        CAPTURE_HTML.format(phrase=phrase),
        height=320,
        scrolling=False,
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        raw = st.text_area(
            "Paste captured JSON here (or use the synthetic button →)",
            key=f"{state_key}_raw",
            height=80,
            placeholder='[{"key": "h", "down": 1.234, "up": 1.298}, ...]',
        )
    with col2:
        st.write("")
        st.write("")
        if st.button("Use synthetic capture", key=f"{state_key}_synth",
                     help="Deterministic, plausible keystroke stream — useful for testing the protocol when you can't type into the iframe."):
            ev = _synthetic_capture(seed=hash(state_key) & 0xFFFF)
            st.session_state[f"{state_key}_synth_cache"] = ev
            st.success(f"Generated {len(ev)} synthetic events.")

    if raw.strip():
        try:
            events = json.loads(raw)
            if isinstance(events, list) and events:
                return events
            st.warning("JSON parsed but did not contain a non-empty event list.")
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc.msg}")

    if st.session_state.get(f"{state_key}_synth_cache"):
        return st.session_state[f"{state_key}_synth_cache"]

    return None


def _synthetic_capture(seed: int = 0) -> list[dict]:
    """Deterministic, plausible keystroke stream for offline testing."""
    rng = np.random.default_rng(seed)
    t = time.time()
    events = []
    keys = list("the quick brown fox jumps over the lazy dog")
    for ch in keys:
        dwell = float(rng.uniform(0.05, 0.13))
        flight = float(rng.uniform(0.04, 0.16))
        events.append({"key": ch, "down": t, "up": t + dwell})
        t += dwell + flight
    return events


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #


def page_home(proto: ProofProtocol) -> None:
    st.title("PROOF — The UPI of Human Verification")
    st.markdown(
        """
**PROOF** replaces CAPTCHA with a portable, device-bound, zero-knowledge
proof of humanity. One-time enrollment, then *any* relying party can ask
*any* validator on the open network: *“is this a human-controlled
device?”* — and get a yes/no answer without ever learning **who** the
human is.
"""
    )

    s = proto.stats()
    cols = st.columns(5)
    cols[0].metric("Enrolled devices", s["devices"])
    cols[1].metric("Active tokens", s["tokens_active"])
    cols[2].metric("Revoked tokens", s["tokens_revoked"])
    cols[3].metric("Active validators", s["validators"])
    pass_rate = (
        100.0 * s["verifications_passed"] / s["verifications_total"]
        if s["verifications_total"] else 0.0
    )
    cols[4].metric("Verifications", s["verifications_total"], f"{pass_rate:.0f}% pass")

    st.divider()
    st.subheader("The five layers")
    layers = [
        ("Behavioral DNA", "60-second keystroke capture → 10-D feature vector with tremor-band spectral power and entropy."),
        ("Pedersen Commitment", "C = m·G + r·H over secp256k1 — perfectly hides the human signal, computationally binding."),
        ("Zero-Knowledge Proof", "Sigma-protocol Schnorr proof of knowledge of (m, r) via Fiat–Shamir. No PII leaves the device."),
        ("Device-Bound Enclave", "AES-256-GCM seal, PBKDF2-derived key, blob bound to device fingerprint — stolen blob is useless."),
        ("Open Validator Network", "NPCI-style: any operator runs a node. 2/3 quorum required. Each attestation is independently signed."),
    ]
    for name, desc in layers:
        st.markdown(f"**{name}** — {desc}")

    st.divider()
    st.subheader("Trust-tier marketplace")
    tier_rows = []
    for p in proto.all_tier_policies():
        tier_rows.append({
            "Tier": p.name.value,
            "Lifetime": _human_seconds(p.token_lifetime_seconds),
            "Min reputation": p.min_reputation,
            "Identity link": "Required" if p.requires_identity_link else "—",
            "Use cases": p.description,
        })
    st.dataframe(pd.DataFrame(tier_rows), hide_index=True, use_container_width=True)


def page_enroll(proto: ProofProtocol) -> None:
    st.title("1.  Enroll device")
    st.caption(
        "Performed once per device-human pair. The captured behavioral signal "
        "is hashed, committed to over secp256k1, and the opening is sealed "
        "inside the enclave. **No biometric data leaves this device.**"
    )

    ss = st.session_state
    pw = st.text_input(
        "Enclave passphrase",
        type="password",
        value=ss.passphrase,
        help="Used to derive the AES key that seals your device key and behavioral commitment.",
    )
    ss.passphrase = pw

    phrase = st.text_input(
        "Calibration phrase (type this in the box below)",
        value="the quick brown fox jumps over the lazy dog",
    )

    events = keystroke_collector(phrase, state_key="enroll")

    if st.button("Enroll device", type="primary", disabled=not (events and pw)):
        try:
            enrollment, bv = proto.enroll_device(ss.machine_signals, pw, events)
            ss.device_id = enrollment.device_id
            st.success(f"Enrolled device `{enrollment.device_id}`.")
            st.markdown("**Device public key** (secp256k1, compressed):")
            st.code(enrollment.public_key_hex, language="text")
            st.markdown("**Behavioral commitment** (secp256k1 point):")
            st.code(enrollment.commitment_hex, language="text")
            _render_feature_chart(bv.features, title="Enrolled behavioral feature vector")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Enrollment failed: {exc}")

    if ss.device_id:
        st.info(f"Active device this session: `{ss.device_id}`")


def page_issue(proto: ProofProtocol) -> None:
    st.title("2.  Issue PROOF token")
    ss = st.session_state
    if not ss.device_id:
        st.warning("Enroll a device first.")
        return

    tier = st.selectbox(
        "Trust tier",
        options=[t.value for t in Tier],
        index=0,
    )
    tier_enum = Tier(tier)
    p = POLICIES[tier_enum]
    st.caption(p.description + f"  •  Lifetime: {_human_seconds(p.token_lifetime_seconds)}")

    rp = st.text_input("Relying-party challenge",
                       value="example.com:login:" + uuid.uuid4().hex[:8],
                       help="A unique, per-request string that binds the proof to this verification context.")
    pw = st.text_input("Enclave passphrase", type="password", value=ss.passphrase)

    events = keystroke_collector(
        "the quick brown fox jumps over the lazy dog",
        state_key="issue",
    )

    if st.button("Generate proof", type="primary", disabled=not (events and pw)):
        try:
            token, live_bv, distance = proto.issue_token(
                device_id=ss.device_id,
                passphrase=pw,
                raw_events=events,
                tier=tier_enum,
                relying_party_challenge=rp.encode("utf-8"),
            )
            ss.issued_token = token
            ss.issued_token_json = token.to_json()
            ss.last_distance = distance
            ss.last_live_features = live_bv.features

            st.success(f"Issued **{token.token_id}** for tier **{tier}**.")
            cols = st.columns(3)
            cols[0].metric("Cosine distance", f"{distance:.4f}", help=f"Threshold: {MATCH_THRESHOLD:.2f}")
            cols[1].metric("Tier", tier)
            cols[2].metric("Expires in", _human_seconds(int(token.expires_at - time.time())))

            _render_feature_chart(live_bv.features, title="Live behavioral capture (this session)")

            st.markdown("### Token JSON")
            st.caption("Copy this; paste it into the Verify tab to simulate a relying party.")
            st.code(token.to_json(), language="json")
        except PermissionError as exc:
            st.error(f"Tier policy refused issuance: {exc}")
        except ValueError as exc:
            st.error(str(exc))
        except Exception as exc:  # noqa: BLE001
            st.exception(exc)


def page_verify(proto: ProofProtocol) -> None:
    st.title("3.  Verify (relying party view)")
    st.caption(
        "A relying party submits a token to the PROOF Network. Each "
        "validator re-runs the full cryptographic check and signs its "
        "verdict. A 2/3 quorum is required."
    )
    ss = st.session_state
    requester = st.text_input("Relying-party identifier", value="example.com")

    default_blob = ss.issued_token_json or ""
    blob = st.text_area("Token JSON", value=default_blob, height=260)

    col1, col2 = st.columns(2)
    if col1.button("Submit to PROOF Network", type="primary", disabled=not blob.strip()):
        try:
            token = ProofToken.from_json(blob)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Cannot parse token: {exc}")
            return
        result = proto.verify_token(token, requester=requester)
        ss.last_quorum = result
        if result.valid:
            st.success(f"VALID ✓ — quorum {result.yes}/{result.total} (threshold {result.threshold}).")
        else:
            st.error(f"REJECTED ✗ — {result.failure_reason} ({result.yes}/{result.total} agreed)")

        _render_quorum_table(result)

    if col2.button("Tamper test (flip 1 bit in signature)", disabled=not blob.strip()):
        try:
            token = ProofToken.from_json(blob)
            token.device_signature = type(token.device_signature)(
                R=token.device_signature.R,
                s=token.device_signature.s ^ 1,
            )
        except Exception as exc:  # noqa: BLE001
            st.error(f"Cannot parse token: {exc}")
            return
        result = proto.verify_token(token, requester=requester + " (tamper test)")
        if result.valid:
            st.warning("Unexpected: tampered token accepted.")
        else:
            st.success(f"Tampered token correctly rejected — {result.failure_reason}")
        _render_quorum_table(result)


def page_network(proto: ProofProtocol) -> None:
    st.title("4.  Validator network")
    st.caption("Open, NPCI-style. Any organisation can run a node. 2/3 quorum.")

    validators = proto.network.active_validators()
    if validators:
        rows = [{
            "Validator ID": v.validator_id,
            "Operator": v.operator,
            "Region": v.region,
            "Public key": v.public_key.to_bytes().hex(),
        } for v in validators]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.caption(f"Quorum threshold: **{proto.network.threshold()} of {len(validators)}**")
    else:
        st.info("No active validators. Add one below.")

    with st.form("add_validator", clear_on_submit=True):
        st.subheader("Onboard a new validator")
        op = st.text_input("Operator name", value="State Bank of India")
        region = st.text_input("Region", value="ap-south-1")
        if st.form_submit_button("Add validator", type="primary"):
            v = proto.network.add_validator(op, region)
            st.success(f"Added validator {v.validator_id} ({op}).")
            st.rerun()

    if validators:
        st.subheader("Decommission")
        target = st.selectbox("Validator to remove", [v.validator_id for v in validators])
        if st.button("Remove", type="secondary"):
            if proto.network.remove_validator(target):
                st.warning(f"Removed {target}.")
                st.rerun()


def page_admin(proto: ProofProtocol) -> None:
    st.title("5.  Admin · revocation · reputation")

    st.subheader("Issued tokens")
    tokens = proto.db.list_tokens()
    if not tokens:
        st.info("No tokens issued yet.")
    else:
        df = pd.DataFrame([{
            "token_id": t["token_id"],
            "device_id": t["device_id"],
            "tier": t["tier"],
            "issued_at": _ts(t["issued_at"]),
            "expires_at": _ts(t["expires_at"]),
            "revoked": bool(t["revoked"]),
            "revoked_reason": t["revoked_reason"] or "",
        } for t in tokens])
        st.dataframe(df, hide_index=True, use_container_width=True)

        with st.form("revoke_form", clear_on_submit=True):
            st.markdown("**Revoke a token**")
            tid = st.selectbox("Token", [t["token_id"] for t in tokens if not t["revoked"]] or ["—"])
            reason = st.text_input("Reason", value="user-requested")
            if st.form_submit_button("Revoke"):
                if tid != "—" and proto.revoke_token(tid, reason):
                    st.success(f"Revoked {tid}.")
                    st.rerun()
                else:
                    st.error("Could not revoke (already revoked or unknown).")

    st.subheader("Devices & reputation")
    devs = proto.db.list_devices()
    if devs:
        rows = []
        for d in devs:
            rep = proto.db.get_reputation(d["device_id"])
            premium = proto.db.get_premium(d["device_id"])
            rows.append({
                "device_id": d["device_id"],
                "enrolled_at": _ts(d["enrolled_at"]),
                "reputation": f"{rep['score']:.1f}" if rep else "—",
                "successful_uses": rep["successful_uses"] if rep else 0,
                "abuse_reports": rep["abuse_reports"] if rep else 0,
                "premium_linked": "yes" if premium else "no",
            })
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    else:
        st.info("No devices enrolled yet.")

    st.subheader("Premium identity link (opt-in)")
    if devs:
        with st.form("link_premium", clear_on_submit=True):
            target = st.selectbox("Device", [d["device_id"] for d in devs])
            aadhaar = st.text_input("Aadhaar number (will be salted-hashed)")
            upi = st.text_input("UPI handle", placeholder="user@upi")
            dl = st.text_input("DigiLocker ID")
            if st.form_submit_button("Link identity"):
                try:
                    proto.link_premium_identity(
                        target, aadhaar.strip() or None, upi.strip() or None, dl.strip() or None
                    )
                    st.success("Identity link recorded (Aadhaar stored only as a salted hash).")
                except Exception as exc:  # noqa: BLE001
                    st.error(str(exc))


def page_sites(proto: ProofProtocol) -> None:
    st.title("7.  Site keys (relying parties)")
    st.caption(
        "Register a website that wants to drop the PROOF widget on its login "
        "page. You receive a public **site key** (embedded in the widget) and a "
        "private **secret key** (used by your backend to verify tokens via "
        "/api/siteverify)."
    )

    with st.form("register_site", clear_on_submit=True):
        c1, c2 = st.columns(2)
        label = c1.text_input("Label", value="My Site")
        domain = c2.text_input("Domain", value="example.com")
        min_action = st.selectbox(
            "Minimum required action",
            [a.value for a in Action], index=0,
            help="The strictest action this site will accept. ALLOW = even "
                 "fast-path verifications are accepted; CHALLENGE = require "
                 "an interactive challenge for every visitor.",
        )
        if st.form_submit_button("Register site", type="primary"):
            site = proto.sites.register(label=label, domain=domain, min_action=min_action)
            st.success(f"Registered **{site.label}** at `{site.domain}`")
            st.markdown("**Site key** (public, embedded in widget JS):")
            st.code(site.site_key, language="text")
            st.markdown("**Secret key** (private, save this now — it is not shown again):")
            st.code(site.secret_key, language="text")

    st.divider()
    st.subheader("Registered sites")
    sites = proto.sites.list()
    if not sites:
        st.info("No sites registered yet.")
        return
    rows = []
    for s in sites:
        rate = (100.0 * s.blocks / s.requests) if s.requests else 0.0
        rows.append({
            "label": s.label, "domain": s.domain,
            "site_key": s.site_key,
            "min_action": s.min_action,
            "active": s.active,
            "requests": s.requests,
            "blocks": s.blocks,
            "block_rate": f"{rate:.1f}%",
            "created": _ts(s.created_at),
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


def page_integration(proto: ProofProtocol) -> None:
    st.title("8.  Integration — drop in 4 lines")
    sites = proto.sites.list()
    if not sites:
        st.info("Register a site first (page 7).")
        return
    site = next((s for s in sites if (
        st.selectbox("Site", [s.label + "  ·  " + s.site_key[:14] + "…" for s in sites], key="int_site")
        .startswith(s.label + "  ·  " + s.site_key[:14])
    )), sites[0])

    api = _api_base()

    st.subheader("Frontend (HTML)")
    st.caption("Drop these two tags anywhere in your page. The widget renders a "
               "Cloudflare-style 'Verify you are human' checkbox.")
    st.code(
        f'''<script src="{api}/api/widget.js" async defer></script>
<div id="proof-widget"></div>
<script>
  PROOF.render("proof-widget", {{
    sitekey: "{site.site_key}",
    callback: function(token) {{
      document.getElementById("proof-token").value = token;
    }}
  }});
</script>
<input type="hidden" id="proof-token" name="proof-response" />''',
        language="html",
    )

    st.subheader("Backend verification (Python · requests)")
    st.code(
        f'''import requests
r = requests.post(
    "{api}/api/siteverify",
    data={{
        "secret":   "<your secret key — keep this server-side>",
        "response": request.form["proof-response"],
        "remoteip": request.remote_addr,
    }},
).json()
if r["success"]:
    print("Verified human · score", r["score"], "· action", r["action"])
else:
    abort(403, "Bot or low confidence: " + ",".join(r["error-codes"]))''',
        language="python",
    )

    st.subheader("Backend verification (curl, for any stack)")
    st.code(
        f'''curl -X POST {api}/api/siteverify \\
  -d secret=<YOUR_SECRET_KEY> \\
  -d response=<TOKEN_FROM_WIDGET>''',
        language="bash",
    )


def page_live_widget(proto: ProofProtocol) -> None:
    st.title("9.  Live widget demo")
    st.caption(
        "The widget shown below is the same JS bundle every relying party "
        "embeds. It collects browser telemetry, solves a silent proof-of-work, "
        "and submits to the public API. **This is the real widget, not a mock.**"
    )

    sites = proto.sites.list()
    if not sites:
        st.warning("Register a site first (page 7) to obtain a sitekey.")
        return
    sitekey = st.selectbox(
        "Use sitekey", [s.site_key for s in sites],
        format_func=lambda k: next(s.label for s in sites if s.site_key == k) + "  ·  " + k[:18] + "…",
    )

    api = _api_base()
    st.caption(f"API base: `{api}`")

    st.subheader("Open the Cloudflare-style verification interstitial")
    st.write(
        "Click **Open** below to open the *real* PROOF interstitial in a new "
        "tab — the same kind of `Performing security verification` page "
        "Cloudflare shows. It will run a live PoW + telemetry + risk-engine "
        "check on your browser, then redirect to the protected page on "
        "success or show a Cloudflare-style block screen on failure."
    )
    open_url = f"{api}/verify?sitekey={sitekey}&destination=/protected"
    st.markdown(
        f'<a href="{open_url}" target="_blank" rel="noopener" '
        f'style="display:inline-block;background:#3da25f;color:#fff;'
        f'padding:10px 22px;border-radius:4px;text-decoration:none;'
        f'font-weight:700;font-size:15px;margin:6px 0 14px;">Open</a>',
        unsafe_allow_html=True,
    )
    st.caption(f"Opens: `{open_url}`")

    st.divider()
    st.subheader("Embedded inline widget (checkbox flow)")

    components.html(
        f"""
        <script src="{api}/api/widget.js" async defer></script>
        <div id="proof-demo" style="margin: 10px 0;"></div>
        <pre id="proof-out" style="background:#0b1020;color:#9ce39c;padding:10px;
             border-radius:6px;font-size:12px;max-height:240px;overflow:auto;"></pre>
        <script>
          function tryRender() {{
            if (!window.PROOF) {{ setTimeout(tryRender, 100); return; }}
            window.PROOF.render("proof-demo", {{
              sitekey: "{sitekey}",
              callback: function(token) {{
                document.getElementById("proof-out").innerText =
                  "response_token = " + token + "\\n\\n" +
                  "Now your backend would POST {{secret, response}} to /api/siteverify";
              }}
            }});
          }}
          tryRender();
        </script>
        """,
        height=320,
    )

    st.divider()
    st.subheader("Or test the API directly from this page")
    st.write("Useful when the iframe widget cannot reach the API server "
             "(e.g. when running locally without the FastAPI workflow up).")

    if st.button("Run a synthetic /siteverify-front call"):
        from proof_protocol.proof_of_work import solve
        from proof_protocol.telemetry import analyze
        with st.spinner("Issuing PoW challenge, solving, and evaluating telemetry…"):
            ch = proto.pow.issue()
            sol = solve(ch)
            tele = analyze({
                "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                "platform": "Linux x86_64",
                "languages": ["en-US", "en"], "languagesCount": 2,
                "pluginsCount": 5, "hardwareConcurrency": 8, "deviceMemory": 8,
                "screenWidth": 1920, "screenHeight": 1080, "colorDepth": 24,
                "pixelRatio": 2, "touchSupport": False,
                "timezone": "Asia/Kolkata", "timezoneOffsetMinutes": 330,
                "webdriver": False, "chromeRuntime": True,
                "automationProps": [],
                "canvasHash": "abc123" * 12,
                "webglRenderer": "Apple M2", "webglVendor": "Apple",
                "audioHash": "35.7449712753",
                "fontsDetected": 24, "rtcLocalIp": "192.168.1.27",
                "pointerIntervalsMs": [12.4, 14.1, 9.8, 22.3, 18.7, 15.2, 11.8, 19.0],
                "scrollCount": 4, "focusEvents": 1,
                "challengeSolveMs": int(sol.elapsed_seconds * 1000),
                "requestAgeSeconds": 0.6,
                "batteryPresent": True, "connectionRttMs": 50,
            })
            verdict = proto.evaluate_visitor(
                site_key=sitekey, challenge=ch, solution=sol,
                telemetry=tele, requester="streamlit-demo",
            )
        c1, c2, c3 = st.columns(3)
        c1.metric("Action", verdict["action"])
        c2.metric("Risk score", f"{verdict['score']:.1f}")
        c3.metric("Success", "✓" if verdict["success"] else "✗")
        st.markdown("**Component scores**")
        st.json(verdict["components"])
        st.markdown("**Risk reasons**")
        for r in verdict["reasons"][:8]:
            st.write("• " + r)
        st.markdown("**Browser fingerprint**")
        st.code(verdict["fingerprint"])
        st.caption("response_token (one-time, 5 min TTL): " + verdict["response_token"])


def page_audit(proto: ProofProtocol) -> None:
    st.title("6.  Audit log & verification history")

    st.subheader("Recent verifications")
    rows = proto.db.recent_verifications(limit=100)
    if rows:
        df = pd.DataFrame([{
            "ts": _ts(r["ts"]),
            "token_id": r["token_id"],
            "requester": r["requester"],
            "valid": bool(r["valid"]),
        } for r in rows])
        st.dataframe(df, hide_index=True, use_container_width=True)
    else:
        st.info("No verifications recorded.")

    st.subheader("Audit log")
    rows = proto.db.recent_audit(limit=100)
    if rows:
        df = pd.DataFrame([{
            "ts": _ts(r["ts"]),
            "actor": r["actor"],
            "action": r["action"],
            "detail": r["detail"],
        } for r in rows])
        st.dataframe(df, hide_index=True, use_container_width=True)
    else:
        st.info("Audit log is empty.")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ts(t: float | None) -> str:
    if t is None:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t)))


def _human_seconds(s: int) -> str:
    if s <= 0:
        return "expired"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _render_feature_chart(features: tuple[float, ...], title: str) -> None:
    df = pd.DataFrame({"feature": FEATURE_NAMES, "value": features})
    fig = px.bar(df, x="feature", y="value", title=title)
    fig.update_layout(xaxis_tickangle=-30, height=320, margin=dict(l=10, r=10, t=40, b=10))
    st.plotly_chart(fig, use_container_width=True)


def _render_quorum_table(result) -> None:
    df = pd.DataFrame([{
        "validator_id": a.validator_id,
        "decision": "ACCEPT" if a.decision else "REJECT",
        "reason": a.reason,
        "ts": _ts(a.timestamp),
        "signature_R": a.signature.R.to_bytes().hex()[:32] + "…",
    } for a in result.attestations])
    st.dataframe(df, hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main() -> None:
    st.set_page_config(
        page_title="PROOF — Human Verification Protocol",
        page_icon="🛡️",
        layout="wide",
    )
    init_state()
    proto = get_protocol()

    with st.sidebar:
        st.markdown("### PROOF Protocol v1.0")
        st.caption("Pure-Python reference implementation.")
        page = st.radio(
            "Navigate",
            options=[
                "Overview",
                "1. Enroll",
                "2. Issue token",
                "3. Verify (relying party)",
                "4. Validator network",
                "5. Admin",
                "6. Audit log",
                "7. Sites",
                "8. Integration",
                "9. Live widget",
            ],
        )
        st.divider()
        st.caption("This session's synthetic device fingerprint:")
        st.code(st.session_state.machine_signals["session_uuid"][:16] + "…", language="text")

    pages = {
        "Overview": page_home,
        "1. Enroll": page_enroll,
        "2. Issue token": page_issue,
        "3. Verify (relying party)": page_verify,
        "4. Validator network": page_network,
        "5. Admin": page_admin,
        "6. Audit log": page_audit,
        "7. Sites": page_sites,
        "8. Integration": page_integration,
        "9. Live widget": page_live_widget,
    }
    pages[page](proto)


if __name__ == "__main__":
    main()
