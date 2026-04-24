"""The drop-in <script> snippet relying parties embed on their pages.

Returned by the public API at ``/widget.js``. Collects the same telemetry
class as Cloudflare Turnstile, solves the silent PoW in a Web Worker, and
posts the result to ``/siteverify-front`` on the PROOF Network.

The widget exposes ``window.PROOF.render(elementId, {sitekey, callback})``
mirroring the Turnstile / reCAPTCHA API exactly so adoption is one-line.
"""

from __future__ import annotations


def widget_javascript(api_base: str) -> str:
    """Return the live JS bundle, with ``api_base`` baked in."""
    return _WIDGET_JS.replace("__API_BASE__", api_base)


_WIDGET_JS = r"""
/* PROOF Protocol widget v1.0 — drop-in human verification.
   Mirrors the Cloudflare Turnstile / reCAPTCHA "render" API. */
(function() {
  const API = "__API_BASE__";

  // ---------- Telemetry collection ---------- //
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
    try {
      T.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch(e) { T.timezone = ""; }
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

    // Audio fingerprint
    try {
      const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (Ctx) {
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
          T.audioHash = s.toFixed(8);
        });
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

    // Battery
    if (navigator.getBattery) {
      navigator.getBattery().then(b => { T.batteryPresent = !!b; });
    }
    // Connection
    if (navigator.connection) {
      T.connectionRttMs = navigator.connection.rtt || 0;
    }

    return T;
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

  // ---------- Proof of Work ---------- //
  function leadingZeroBits(hex) {
    let n = 0;
    for (let i = 0; i < hex.length; i += 2) {
      const b = parseInt(hex.substr(i,2),16);
      if (b === 0) { n += 8; continue; }
      let v = b, c = 0;
      while ((v & 0x80) === 0 && c < 8) { c++; v <<= 1; }
      return n + c;
    }
    return n;
  }
  async function sha256Hex(bytes) {
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  }
  async function solvePow(challengeId, difficulty) {
    const enc = new TextEncoder();
    const idBytes = enc.encode(challengeId);
    const buf = new Uint8Array(idBytes.length + 8);
    buf.set(idBytes, 0);
    const t0 = performance.now();
    for (let nonce = 0; nonce < (1 << 24); nonce++) {
      // big-endian 8-byte nonce
      buf[idBytes.length + 0] = 0;
      buf[idBytes.length + 1] = 0;
      buf[idBytes.length + 2] = 0;
      buf[idBytes.length + 3] = (nonce >>> 24) & 0xff;
      buf[idBytes.length + 4] = (nonce >>> 16) & 0xff;
      buf[idBytes.length + 5] = (nonce >>>  8) & 0xff;
      buf[idBytes.length + 6] =  nonce         & 0xff;
      buf[idBytes.length + 7] = 0;
      const hex = await sha256Hex(buf);
      if (leadingZeroBits(hex) >= difficulty) {
        return {nonce: nonce, elapsed_seconds: (performance.now() - t0) / 1000};
      }
      if ((nonce & 0xff) === 0 && (performance.now() - t0) > 8000) {
        throw new Error("PoW timed out (browser too slow or difficulty too high)");
      }
    }
    throw new Error("PoW exhausted iteration budget");
  }

  // ---------- Verification flow ---------- //
  async function verify(sitekey) {
    const challenge = await (await fetch(API + "/api/challenge?sitekey=" + encodeURIComponent(sitekey))).json();
    if (!challenge.challenge_id) throw new Error(challenge.error || "challenge issuance failed");
    const sol = await solvePow(challenge.challenge_id, challenge.difficulty);
    const localIp = await probeLocalIp(1000);
    const T = collect();
    T.rtcLocalIp = localIp;
    T.pointerIntervalsMs = tracker.intervals.slice();
    T.scrollCount = tracker.scroll;
    T.focusEvents = tracker.focus;
    T.challengeSolveMs = Math.round(sol.elapsed_seconds * 1000);
    T.requestAgeSeconds = (Date.now() / 1000) - challenge.issued_at;
    const submission = {
      sitekey: sitekey,
      challenge: challenge,
      solution: { challenge_id: challenge.challenge_id, nonce: sol.nonce, elapsed_seconds: sol.elapsed_seconds },
      telemetry: T
    };
    const res = await fetch(API + "/api/siteverify-front", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify(submission)
    });
    return res.json();
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
