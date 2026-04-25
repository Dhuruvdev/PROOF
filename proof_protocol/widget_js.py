"""The drop-in <script> snippet relying parties embed on their pages.

Returned by the public API at ``/api/widget.js``. Collects the same telemetry
class as Cloudflare Turnstile, hashes the verbatim telemetry JSON, solves a
silent PoW whose hashed input is bound to (challenge_id, sitekey,
telemetry_hash), and posts the result + the raw telemetry string to
``/api/siteverify-front``. The server recomputes the hash, so a client
cannot solve the PoW with one telemetry blob and submit a different one.

The widget exposes ``window.PROOF.render(elementId, {sitekey, callback})``
mirroring the Turnstile / reCAPTCHA API exactly so adoption is one-line.
"""

from __future__ import annotations


def widget_javascript(api_base: str) -> str:
    """Return the live JS bundle, with ``api_base`` baked in."""
    return _WIDGET_JS.replace("__API_BASE__", api_base)


_WIDGET_JS = r"""
/* PROOF Protocol widget v1.1 — drop-in human verification.
   Mirrors the Cloudflare Turnstile / reCAPTCHA "render" API. */
(function() {
  "use strict";
  const API = "__API_BASE__";

  // ---------- Telemetry collection (sync; Promise-resolving fields await separately) ---------- //
  function collect() {
    const T = {};
    T.userAgent = navigator.userAgent || "";
    T.platform = navigator.platform || "";
    T.languages = navigator.languages || (navigator.language ? [navigator.language] : []);
    T.languagesCount = T.languages.length;
    T.pluginsCount = (navigator.plugins && navigator.plugins.length) || 0;
    T.hardwareConcurrency = navigator.hardwareConcurrency || 0;
    T.deviceMemory = navigator.deviceMemory || 0;
    T.screenWidth = (window.screen && window.screen.width) || 0;
    T.screenHeight = (window.screen && window.screen.height) || 0;
    T.colorDepth = (window.screen && window.screen.colorDepth) || 0;
    T.pixelRatio = window.devicePixelRatio || 1;
    T.touchSupport = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
    try { T.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; }
    catch(e) { T.timezone = ""; }
    T.timezoneOffsetMinutes = -(new Date()).getTimezoneOffset();

    // Automation surfaces
    T.webdriver = !!navigator.webdriver;
    T.chromeRuntime = !!(window.chrome && window.chrome.runtime);
    const surfaces = [
      "_phantom","callPhantom","__nightmare","domAutomation","domAutomationController",
      "_selenium","_Selenium_IDE_Recorder","calledSelenium","$cdc_asdjflasutopfhvcZLmcfl_",
      "$chrome_asyncScriptInfo","__webdriver_evaluate","__driver_evaluate",
      "__webdriver_script_function","__webdriver_script_func","__fxdriver_evaluate",
      "__driver_unwrapped","__webdriver_unwrapped","__fxdriver_unwrapped",
      "__playwright","__pwInitScripts","puppeteer"
    ];
    T.automationProps = surfaces.filter(p => p in window || p in document);

    // Canvas fingerprint
    try {
      const c = document.createElement("canvas");
      c.width = 280; c.height = 60;
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125,1,62,20);
      ctx.fillStyle = "#069";
      ctx.fillText("PROOF \u2728 \u00A9 \u2603", 4, 17);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("PROOF \u2728 \u00A9 \u2603", 4, 17);
      T.canvasHash = c.toDataURL().split(",")[1].slice(-128);
    } catch(e) { T.canvasHash = ""; }

    // WebGL fingerprint
    try {
      const gl = document.createElement("canvas").getContext("webgl") ||
                 document.createElement("canvas").getContext("experimental-webgl");
      if (gl) {
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        if (dbg) {
          T.webglRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "");
          T.webglVendor   = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "");
        } else {
          T.webglRenderer = String(gl.getParameter(gl.RENDERER) || "");
          T.webglVendor   = String(gl.getParameter(gl.VENDOR) || "");
        }
      }
    } catch(e) {}

    // Font enumeration (best-effort offsetWidth probe)
    try {
      const tests = ["Arial","Times","Courier","Verdana","Helvetica","Comic Sans MS",
                     "Trebuchet MS","Georgia","Palatino","Garamond","Bookman",
                     "Tahoma","Impact","Andale Mono","Apple Chancery","Brush Script MT",
                     "Copperplate","Geneva","Hoefler Text","Optima","Lucida Console",
                     "Monaco","Menlo","Consolas","Roboto","Noto Sans","Inter",
                     "SF Pro","Source Sans Pro","Source Code Pro","Fira Code"];
      const baseline = ["monospace","sans-serif","serif"];
      const span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;font-size:72px;";
      span.innerHTML = "mmmmmmmmmmlli";
      document.body.appendChild(span);
      const baselineWidths = {};
      baseline.forEach(b => { span.style.fontFamily = b; baselineWidths[b] = span.offsetWidth; });
      let detected = 0;
      tests.forEach(f => {
        let isInstalled = false;
        baseline.forEach(b => {
          span.style.fontFamily = "'" + f + "'," + b;
          if (span.offsetWidth !== baselineWidths[b]) isInstalled = true;
        });
        if (isInstalled) detected++;
      });
      document.body.removeChild(span);
      T.fontsDetected = detected;
    } catch(e) { T.fontsDetected = 0; }

    if (navigator.connection) {
      T.connectionRttMs = navigator.connection.rtt || 0;
    }
    return T;
  }

  // Audio fingerprint — async, started in parallel with PoW.
  async function audioHash() {
    return new Promise(resolve => {
      try {
        const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!Ctx) return resolve("");
        const ctx = new Ctx(1, 5000, 44100);
        const osc = ctx.createOscillator();
        osc.type = "triangle"; osc.frequency.setValueAtTime(10000, 0);
        const comp = ctx.createDynamicsCompressor();
        comp.threshold.setValueAtTime(-50, 0);
        comp.knee.setValueAtTime(40, 0);
        comp.ratio.setValueAtTime(12, 0);
        comp.attack.setValueAtTime(0, 0);
        comp.release.setValueAtTime(0.25, 0);
        osc.connect(comp); comp.connect(ctx.destination);
        osc.start(0);
        ctx.startRendering().then(buf => {
          const data = buf.getChannelData(0);
          let s = 0;
          for (let i = 4500; i < 5000; i++) s += Math.abs(data[i]);
          resolve(s.toFixed(8));
        }).catch(() => resolve(""));
      } catch (e) { resolve(""); }
    });
  }

  // ---------- WebRTC local IP probe ---------- //
  function probeLocalIp(timeoutMs) {
    return new Promise(resolve => {
      let ip = "";
      try {
        const pc = new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
        pc.createDataChannel("");
        pc.createOffer().then(o => pc.setLocalDescription(o)).catch(()=>{});
        pc.onicecandidate = (e) => {
          if (!e || !e.candidate) return;
          const m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+|[a-fA-F0-9:]+:[a-fA-F0-9:]+)/);
          if (m && !ip) { ip = m[1]; }
        };
        setTimeout(() => { try { pc.close(); } catch(e) {} resolve(ip); }, timeoutMs || 1200);
      } catch (e) { resolve(""); }
    });
  }

  // ---------- Behavioral pointer / scroll tracking ---------- //
  const tracker = { intervals: [], lastT: 0, scroll: 0, focus: 0 };
  function startTracking() {
    document.addEventListener("mousemove", () => {
      const t = performance.now();
      if (tracker.lastT > 0) tracker.intervals.push(t - tracker.lastT);
      if (tracker.intervals.length > 800) tracker.intervals.shift();
      tracker.lastT = t;
    }, {passive:true});
    document.addEventListener("scroll", () => tracker.scroll++, {passive:true});
    window.addEventListener("focus", () => tracker.focus++);
    window.addEventListener("blur",  () => tracker.focus++);
  }
  startTracking();

  // ---------- Sync SHA-256 (FIPS 180-4) for the PoW inner loop ---------- //
  // Why not crypto.subtle.digest? SubtleCrypto returns a Promise per call,
  // and each await queues a microtask — at 14 bits (~16K iterations) that's
  // measured in seconds in real Chromium. A tight-loop sync SHA-256 hits
  // ~100K H/s in V8, so the same difficulty solves in ~150 ms.
  // Kept self-contained, no external dependency.
  const _K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  function sha256Sync(msg) {
    // msg: Uint8Array. Returns Uint8Array(32).
    const ml = msg.length;
    const bitLen = ml * 8;
    // Pad to (multiple of 64) - 8 with 0x80 || zeros, then append 64-bit BE length.
    const padded = new Uint8Array(((ml + 9 + 63) >> 6) << 6);
    padded.set(msg, 0);
    padded[ml] = 0x80;
    // Length in bits, big-endian, last 8 bytes. JS bit ops are 32-bit so
    // split into hi/lo 32-bit halves.
    const hi = Math.floor(bitLen / 0x100000000);
    const lo = bitLen >>> 0;
    padded[padded.length - 8] = (hi >>> 24) & 0xff;
    padded[padded.length - 7] = (hi >>> 16) & 0xff;
    padded[padded.length - 6] = (hi >>>  8) & 0xff;
    padded[padded.length - 5] =  hi         & 0xff;
    padded[padded.length - 4] = (lo >>> 24) & 0xff;
    padded[padded.length - 3] = (lo >>> 16) & 0xff;
    padded[padded.length - 2] = (lo >>>  8) & 0xff;
    padded[padded.length - 1] =  lo         & 0xff;

    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
        h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const W = new Uint32Array(64);
    for (let off = 0; off < padded.length; off += 64) {
      for (let t = 0; t < 16; t++) {
        const j = off + (t << 2);
        W[t] = ((padded[j] << 24) | (padded[j+1] << 16) |
                (padded[j+2] << 8) |  padded[j+3]) >>> 0;
      }
      for (let t = 16; t < 64; t++) {
        const x = W[t-15], y = W[t-2];
        const s0 = ((x>>>7)|(x<<25)) ^ ((x>>>18)|(x<<14)) ^ (x>>>3);
        const s1 = ((y>>>17)|(y<<15)) ^ ((y>>>19)|(y<<13)) ^ (y>>>10);
        W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
      }
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
      for (let t = 0; t < 64; t++) {
        const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + _K[t] + W[t]) >>> 0;
        const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
      h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+hh)>>>0;
    }
    const out = new Uint8Array(32);
    const hs = [h0,h1,h2,h3,h4,h5,h6,h7];
    for (let i = 0; i < 8; i++) {
      out[i*4]   = (hs[i] >>> 24) & 0xff;
      out[i*4+1] = (hs[i] >>> 16) & 0xff;
      out[i*4+2] = (hs[i] >>>  8) & 0xff;
      out[i*4+3] =  hs[i]         & 0xff;
    }
    return out;
  }

  async function sha256Hex(bytes) {
    // Async variant kept for telemetry hashing where SubtleCrypto is fine.
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  }

  function leadingZeroBitsBytes(b) {
    let n = 0;
    for (let i = 0; i < b.length; i++) {
      const v = b[i];
      if (v === 0) { n += 8; continue; }
      let c = 0, x = v;
      while ((x & 0x80) === 0 && c < 8) { c++; x <<= 1; }
      return n + c;
    }
    return n;
  }

  /**
   * SHA-256(challenge_id || "|" || sitekey || "|" || telemetry_hash || "|" || nonce_be8)
   * Mirrors `pow_hash_bytes` in proof_of_work.py — sync SHA-256 in inner loop.
   */
  async function solvePow(challengeId, sitekey, telemetryHash, difficulty) {
    const enc = new TextEncoder();
    const headBytes = enc.encode(challengeId + "|" + sitekey + "|" + telemetryHash + "|");
    const buf = new Uint8Array(headBytes.length + 8);
    buf.set(headBytes, 0);
    const noncePos = headBytes.length;
    const t0 = performance.now();
    // We yield to the event loop every 2048 iterations so the page stays
    // responsive (the nonce search is otherwise CPU-bound).
    let nonce = 0;
    while (nonce < (1 << 24)) {
      const end = Math.min(nonce + 2048, 1 << 24);
      for (; nonce < end; nonce++) {
        // big-endian 8-byte nonce (high 32 bits zero — 32-bit search space
        // is ample for difficulty ≤ 26 bits)
        buf[noncePos + 0] = 0; buf[noncePos + 1] = 0;
        buf[noncePos + 2] = 0; buf[noncePos + 3] = 0;
        buf[noncePos + 4] = (nonce >>> 24) & 0xff;
        buf[noncePos + 5] = (nonce >>> 16) & 0xff;
        buf[noncePos + 6] = (nonce >>>  8) & 0xff;
        buf[noncePos + 7] =  nonce         & 0xff;
        const digest = sha256Sync(buf);
        if (leadingZeroBitsBytes(digest) >= difficulty) {
          return {nonce: nonce, elapsed_seconds: (performance.now() - t0) / 1000};
        }
      }
      if ((performance.now() - t0) > 30000) {
        throw new Error("PoW timed out at nonce " + nonce +
                        " (difficulty " + difficulty + " bits)");
      }
      // Yield once per chunk so the UI can paint.
      await new Promise(r => setTimeout(r, 0));
    }
    throw new Error("PoW exhausted iteration budget");
  }

  // Big-endian 8-byte nonce only fits in 32-bit JS integers up to 2^32. The
  // PoW search above uses bytes 4..7 for the nonce; bytes 0..3 stay zero.
  // The Python solver does the same (nonce.to_bytes(8, "big") with nonce
  // in [0, 2^32)) so the two implementations agree on the hashed input.

  // ---------- Verification flow ---------- //
  async function verify(sitekey) {
    if (!sitekey || typeof sitekey !== "string") {
      throw new Error("sitekey is required");
    }
    // 1. Get a fresh challenge bound to this sitekey.
    const challenge = await (await fetch(API + "/api/challenge?sitekey=" +
                                         encodeURIComponent(sitekey))).json();
    if (!challenge.challenge_id) throw new Error(challenge.error || "challenge issuance failed");

    // 2. Collect telemetry. WebRTC + audio in parallel; the rest is sync.
    const T = collect();
    const [localIp, audio] = await Promise.all([
      probeLocalIp(1000),
      audioHash(),
    ]);
    T.rtcLocalIp = localIp;
    T.audioHash = audio;
    T.pointerIntervalsMs = tracker.intervals.slice();
    T.scrollCount = tracker.scroll;
    T.focusEvents = tracker.focus;
    // We commit to the telemetry value before solving the PoW so the server
    // can refuse any post-hoc swap. requestAgeSeconds is computed *after*
    // PoW so we omit it from the hashed body and include it separately.
    const telemetryRaw = JSON.stringify(T);
    const telemetryHashHex = await sha256Hex(new TextEncoder().encode(telemetryRaw));

    // 3. Solve PoW with input bound to (sitekey, telemetry_hash).
    const sol = await solvePow(challenge.challenge_id, sitekey, telemetryHashHex,
                               challenge.difficulty);
    T.challengeSolveMs = Math.round(sol.elapsed_seconds * 1000);
    T.requestAgeSeconds = (Date.now() / 1000) - challenge.issued_at;

    // 4. Submit the verbatim telemetry string + the hash + the solution.
    const submission = {
      sitekey: sitekey,
      challenge: challenge,
      solution: {
        challenge_id: challenge.challenge_id,
        nonce: sol.nonce,
        elapsed_seconds: sol.elapsed_seconds,
        telemetry_hash: telemetryHashHex
      },
      telemetry_raw: telemetryRaw,
      telemetry_hash: telemetryHashHex,
      // Live signals computed after the PoW; the server merges them into
      // telemetry but does not include them in the integrity hash.
      live: {
        challengeSolveMs: T.challengeSolveMs,
        requestAgeSeconds: T.requestAgeSeconds
      }
    };
    const res = await fetch(API + "/api/siteverify-front", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(submission)
    });
    const out = await res.json();
    out.pow_difficulty = challenge.difficulty | 0;
    out.pow_solve_ms = T.challengeSolveMs;
    out.client_ts = Date.now() / 1000;
    return out;
  }

  // ---------- Public render API (Turnstile-compatible signature) ---------- //
  window.PROOF = window.PROOF || {};
  window.PROOF.render = function(elOrId, opts) {
    const el = (typeof elOrId === "string") ? document.getElementById(elOrId) : elOrId;
    if (!el) throw new Error("PROOF.render: element not found");
    el.innerHTML = '<div style="border:1px solid #d1d5db;border-radius:8px;padding:10px 14px;display:inline-flex;align-items:center;gap:10px;font-family:system-ui;background:#fff;">' +
                   '<input type="checkbox" id="proof-cb" style="width:18px;height:18px;cursor:pointer;"/>' +
                   '<label for="proof-cb" style="cursor:pointer;">Verify you are human</label>' +
                   '<div style="margin-left:18px;color:#0066ff;font-weight:700;">PROOF</div>' +
                   '</div><div id="proof-msg" style="margin-top:6px;font-size:12px;color:#666;font-family:system-ui;"></div>';
    const cb = el.querySelector("#proof-cb");
    const msg = el.querySelector("#proof-msg");
    cb.addEventListener("change", async () => {
      if (!cb.checked) return;
      cb.disabled = true; msg.innerText = "Verifying… (silent proof-of-work)";
      try {
        const r = await verify(opts.sitekey);
        if (r.success) {
          msg.innerHTML = '<span style="color:#16a34a;">\u2713 Verified — token: ' + (r.token || "").slice(0,20) + '…</span>';
          if (typeof opts.callback === "function") opts.callback(r.token);
        } else {
          msg.innerHTML = '<span style="color:#dc2626;">\u2717 ' + (r.error || "verification failed") + '</span>';
          cb.checked = false; cb.disabled = false;
          if (typeof opts["error-callback"] === "function") opts["error-callback"](r.error);
        }
      } catch (e) {
        msg.innerHTML = '<span style="color:#dc2626;">\u2717 ' + e.message + '</span>';
        cb.checked = false; cb.disabled = false;
      }
    });
  };
  window.PROOF.verify = verify;
  window.PROOF.collect = collect;
})();
"""
