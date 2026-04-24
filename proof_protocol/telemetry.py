"""Browser environment telemetry — the same signal class Cloudflare
Turnstile, hCaptcha and reCAPTCHA v3 evaluate.

The client (see ``widget_js.py``) collects:

* navigator.userAgent / platform / language / hardwareConcurrency / deviceMemory
* screen size, color depth, devicePixelRatio
* timezone (Intl.DateTimeFormat().resolvedOptions().timeZone) + offset
* canvas fingerprint (2D), WebGL renderer/vendor, audio fingerprint
* installed plugins, mime types, available fonts (probed)
* navigator.webdriver, presence of `chrome`, `Notification`, `chrome.runtime`
* automation surfaces: window._phantom, callPhantom, __nightmare,
  document.$cdc_*, Selenium IDE markers, Playwright/Puppeteer/CDP markers
* WebRTC local IP (via STUN) — leak that bypasses VPN
* event timing entropy: pointer/mouse jitter, scroll, focus blur
* battery, connection (effectiveType, downlink, rtt) where available

All of those are submitted as a single JSON document. This module parses
the document, sanitises it, and produces a deterministic feature vector
plus a list of human-readable risk flags.
"""

from __future__ import annotations

import hashlib
import math
import re
import statistics
from dataclasses import dataclass, field
from typing import Any

from user_agents import parse as parse_ua


# --------------------------------------------------------------------------- #
# Known signatures
# --------------------------------------------------------------------------- #

HEADLESS_UA_PATTERNS = [
    r"\bHeadlessChrome\b",
    r"\bPhantomJS\b",
    r"\bSlimerJS\b",
    r"\bElectron\b",
    r"\bcurl\b",
    r"\bpython-requests\b",
    r"\bGo-http-client\b",
    r"\bbot\b",
    r"\bcrawl",
    r"\bspider\b",
]

AUTOMATION_PROPS = [
    "_phantom",
    "callPhantom",
    "__nightmare",
    "domAutomation",
    "domAutomationController",
    "_selenium",
    "_Selenium_IDE_Recorder",
    "calledSelenium",
    "$cdc_asdjflasutopfhvcZLmcfl_",
    "$chrome_asyncScriptInfo",
    "__webdriver_evaluate",
    "__driver_evaluate",
    "__webdriver_script_function",
    "__webdriver_script_func",
    "__fxdriver_evaluate",
    "__driver_unwrapped",
    "__webdriver_unwrapped",
    "__fxdriver_unwrapped",
    "__playwright",
    "__pwInitScripts",
    "puppeteer",
    "webdriver",
]

KNOWN_BAD_WEBGL = {
    "Brian Paul",  # Mesa default — common in headless
    "Mesa OffScreen",
    "Google SwiftShader",
    "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)),"
    " SwiftShader driver-5.0.0)",
}


@dataclass
class TelemetrySummary:
    feature_vector: list[float]      # numeric — fed to risk engine
    risk_flags: list[str] = field(default_factory=list)
    fingerprint: str = ""            # 32-hex stable per device/browser
    parsed_ua: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    suspicion_score: float = 0.0     # 0 (clean) … 100 (highly suspicious)


# Feature vector layout (kept in this exact order for the ML model):
FEATURE_LAYOUT = (
    "ua_is_known_bot",           # 0/1
    "automation_flag_count",     # int — capped at 10
    "webdriver_present",         # 0/1
    "missing_chrome_runtime",    # 0/1
    "plugins_count",             # int (0 → suspicious)
    "languages_count",           # int (0 → suspicious)
    "fonts_detected",            # int
    "hardware_concurrency",      # int (0 means unknown)
    "device_memory_gb",          # float
    "screen_area_kpx",           # screen_width*height / 1000
    "timezone_consistency",      # 0/1 — does TZ match UA hint
    "canvas_entropy_bits",       # estimated bits of entropy in canvas hash
    "webgl_known_bad",           # 0/1
    "audio_entropy_bits",        # float
    "webrtc_ip_leaked",          # 0/1
    "rtc_local_is_private",      # 0/1
    "pointer_jitter",            # std-dev of mouse-move intervals (ms)
    "pointer_path_length",       # int — number of mouse-move samples
    "scroll_count",              # int
    "focus_events",              # int
    "challenge_solve_ms",        # int — ms spent on PoW (0 = none)
    "ua_age_years",              # how old the UA family is (heuristic)
    "is_mobile",                 # 0/1
    "is_touch_device",           # 0/1
    "battery_present",           # 0/1
    "connection_rtt_ms",         # int (0 unknown)
    "request_age_seconds",       # time between challenge issuance and submission
)


def _flag(flags: list[str], cond: bool, msg: str) -> None:
    if cond:
        flags.append(msg)


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _shannon_bits_of(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h * len(set(s))  # rough total-entropy proxy


def _smallest_period(s: str) -> int:
    """Return the length of the smallest repeating substring of ``s``.

    A real GPU canvas / WebGL / audio fingerprint is the SHA-256 of pixel
    data so its hex string is essentially uniformly distributed — its
    smallest period equals its full length. A fabricated string like
    ``"a1b2c3d4" * 16`` has period 8, which is a dead giveaway.
    """
    n = len(s)
    if n == 0:
        return 0
    for p in range(1, n // 2 + 1):
        if n % p != 0:
            continue
        if s[:p] * (n // p) == s:
            return p
    return n


def _looks_fabricated(hash_str: str) -> bool:
    """Heuristic: a real cryptographic hash never has a small period and
    never has fewer than 8 unique hex characters out of the 16 possible."""
    if not hash_str or len(hash_str) < 16:
        return False  # absence handled by other rules
    period = _smallest_period(hash_str)
    if period < len(hash_str) // 2:
        return True
    unique = len(set(hash_str))
    # SHA-256 hex over real entropy: P(unique<8 in 64 chars) ≈ 1.6e-9
    if len(hash_str) >= 64 and unique < 8:
        return True
    return False


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    if ":" in ip and (ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd")):
        return True
    return False


def analyze(payload: dict[str, Any]) -> TelemetrySummary:
    """Convert a raw telemetry payload into a structured risk summary."""
    flags: list[str] = []
    raw = payload or {}

    # ---- User agent --------------------------------------------------------
    ua_str = str(raw.get("userAgent") or "")
    ua_lower = ua_str.lower()
    ua_is_bot = any(re.search(p, ua_str, re.IGNORECASE) for p in HEADLESS_UA_PATTERNS)
    parsed = parse_ua(ua_str) if ua_str else None
    parsed_dict = {
        "browser": f"{parsed.browser.family} {parsed.browser.version_string}" if parsed else "",
        "os": f"{parsed.os.family} {parsed.os.version_string}" if parsed else "",
        "device": parsed.device.family if parsed else "",
        "is_mobile": bool(parsed and parsed.is_mobile),
        "is_tablet": bool(parsed and parsed.is_tablet),
        "is_pc": bool(parsed and parsed.is_pc),
        "is_bot": bool(parsed and parsed.is_bot) or ua_is_bot,
    }
    _flag(flags, parsed_dict["is_bot"], f"User-Agent matches a known bot pattern: {ua_str[:60]}")
    _flag(flags, "headlesschrome" in ua_lower, "User-Agent advertises HeadlessChrome")

    # ---- Automation surfaces ----------------------------------------------
    auto_props_seen = [p for p in (raw.get("automationProps") or []) if isinstance(p, str)]
    automation_flag_count = min(10, len(auto_props_seen))
    _flag(flags, len(auto_props_seen) > 0,
          f"Automation surfaces present: {', '.join(auto_props_seen[:5])}"
          + (" …" if len(auto_props_seen) > 5 else ""))

    webdriver_present = 1 if raw.get("webdriver") else 0
    _flag(flags, webdriver_present == 1, "navigator.webdriver === true (Selenium/Playwright/Puppeteer)")

    missing_chrome_runtime = 0
    if "Chrome" in (parsed_dict.get("browser") or "") and not raw.get("chromeRuntime"):
        missing_chrome_runtime = 1
        flags.append("Browser claims Chrome but window.chrome.runtime is missing")

    # ---- Hardware / display -----------------------------------------------
    plugins_count = _safe_int(raw.get("pluginsCount"))
    languages_count = _safe_int(raw.get("languagesCount"))
    fonts_detected = _safe_int(raw.get("fontsDetected"))
    hardware_concurrency = _safe_int(raw.get("hardwareConcurrency"))
    device_memory = _safe_float(raw.get("deviceMemory"))
    screen_w = _safe_int(raw.get("screenWidth"))
    screen_h = _safe_int(raw.get("screenHeight"))
    screen_area_kpx = (screen_w * screen_h) / 1000.0
    is_touch = 1 if raw.get("touchSupport") else 0

    _flag(flags, plugins_count == 0 and not parsed_dict["is_mobile"],
          "navigator.plugins is empty on a desktop browser")
    _flag(flags, languages_count == 0, "navigator.languages is empty")
    _flag(flags, fonts_detected < 10 and not parsed_dict["is_mobile"],
          f"Only {fonts_detected} fonts detected — typical of headless")
    _flag(flags, screen_w == 0 or screen_h == 0, "Screen dimensions reported as 0")
    _flag(flags, screen_w == 800 and screen_h == 600,
          "Screen 800×600 — default headless Chrome viewport")
    _flag(flags, hardware_concurrency == 0, "navigator.hardwareConcurrency is unavailable")

    # ---- Timezone consistency ---------------------------------------------
    tz = raw.get("timezone") or ""
    tz_offset = _safe_int(raw.get("timezoneOffsetMinutes"))
    timezone_consistency = 1
    # Cheap heuristic: if UA reports a Windows / Mac OS but tz is "UTC" exactly
    # AND offset is exactly 0, flag (most server-side headless browsers).
    if tz in {"UTC", "Etc/UTC"} and tz_offset == 0 and not parsed_dict["is_mobile"]:
        timezone_consistency = 0
        flags.append("Timezone is exactly UTC with 0 offset — uncommon for real users")

    # ---- Canvas / WebGL / Audio -------------------------------------------
    canvas_hash = str(raw.get("canvasHash") or "")
    canvas_entropy = _shannon_bits_of(canvas_hash)
    canvas_fabricated = _looks_fabricated(canvas_hash)
    _flag(flags, canvas_hash == "" or canvas_entropy < 10,
          "Canvas fingerprint is empty or low-entropy")
    _flag(flags, canvas_fabricated,
          "Canvas fingerprint shows a repeating / low-variety pattern — "
          "real GPU output is uniformly distributed (likely fabricated)")

    webgl_renderer = str(raw.get("webglRenderer") or "")
    webgl_vendor = str(raw.get("webglVendor") or "")
    webgl_known_bad = 1 if any(s in webgl_renderer or s in webgl_vendor for s in KNOWN_BAD_WEBGL) else 0
    _flag(flags, webgl_known_bad == 1,
          f"WebGL renderer is a known headless GPU stub: {webgl_renderer or webgl_vendor}")

    audio_hash = str(raw.get("audioHash") or "")
    audio_entropy = _shannon_bits_of(audio_hash)
    audio_fabricated = _looks_fabricated(audio_hash)
    _flag(flags, audio_hash == "", "AudioContext fingerprint missing")
    _flag(flags, audio_fabricated,
          "AudioContext fingerprint shows a repeating / low-variety pattern")

    # ---- WebRTC ------------------------------------------------------------
    rtc_local = str(raw.get("rtcLocalIp") or "")
    webrtc_ip_leaked = 1 if rtc_local else 0
    rtc_is_private = 1 if _is_private_ip(rtc_local) else 0
    _flag(flags, webrtc_ip_leaked == 0,
          "No WebRTC local IP — headless or aggressive privacy stack")

    # ---- Behavior ---------------------------------------------------------
    pointer_intervals = [float(x) for x in (raw.get("pointerIntervalsMs") or []) if isinstance(x, (int, float))]
    pointer_jitter = (
        statistics.pstdev(pointer_intervals) if len(pointer_intervals) > 2 else 0.0
    )
    pointer_path_length = len(pointer_intervals)
    scroll_count = _safe_int(raw.get("scrollCount"))
    focus_events = _safe_int(raw.get("focusEvents"))

    if pointer_path_length > 0 and pointer_jitter < 0.5:
        flags.append(
            f"Mouse intervals have suspiciously low jitter "
            f"(σ={pointer_jitter:.2f} ms over {pointer_path_length} samples)"
        )
    if pointer_path_length == 0 and not parsed_dict["is_mobile"]:
        flags.append("No mouse activity recorded on a non-mobile browser")

    challenge_solve_ms = _safe_int(raw.get("challengeSolveMs"))
    request_age = _safe_float(raw.get("requestAgeSeconds"))

    # ---- Battery / Connection ---------------------------------------------
    battery_present = 1 if raw.get("batteryPresent") else 0
    connection_rtt_ms = _safe_int(raw.get("connectionRttMs"))

    # ---- UA age (very rough) -----------------------------------------------
    ua_age_years = 0.0
    if parsed:
        try:
            major = int(str(parsed.browser.version[0])) if parsed.browser.version else 0
        except (ValueError, IndexError):
            major = 0
        # Recent Chrome/Edge/Firefox majors are 100+; older majors → larger age
        if major:
            ua_age_years = max(0.0, (140 - major) / 10.0)

    is_mobile = 1 if parsed_dict["is_mobile"] else 0

    feature_vector = [
        1.0 if parsed_dict["is_bot"] else 0.0,
        float(automation_flag_count),
        float(webdriver_present),
        float(missing_chrome_runtime),
        float(plugins_count),
        float(languages_count),
        float(fonts_detected),
        float(hardware_concurrency),
        float(device_memory),
        float(screen_area_kpx),
        float(timezone_consistency),
        float(canvas_entropy),
        float(webgl_known_bad),
        float(audio_entropy),
        float(webrtc_ip_leaked),
        float(rtc_is_private),
        float(pointer_jitter),
        float(pointer_path_length),
        float(scroll_count),
        float(focus_events),
        float(challenge_solve_ms),
        float(ua_age_years),
        float(is_mobile),
        float(is_touch),
        float(battery_present),
        float(connection_rtt_ms),
        float(request_age),
    ]
    assert len(feature_vector) == len(FEATURE_LAYOUT), "Feature layout mismatch"

    # ---- Stable fingerprint ------------------------------------------------
    fp_parts = [
        ua_str,
        canvas_hash,
        webgl_renderer,
        webgl_vendor,
        audio_hash,
        tz,
        str(screen_w), str(screen_h),
        str(hardware_concurrency),
        str(device_memory),
        ",".join(sorted(raw.get("languages") or [])),
    ]
    fingerprint = hashlib.sha256("|".join(fp_parts).encode("utf-8")).hexdigest()[:32]

    # ---- Cheap rule-based suspicion (pre-ML) -------------------------------
    # Fabricated cryptographic-hash strings are the single strongest signal of
    # a hand-crafted forgery: a real GPU/audio context produces uniformly
    # distributed bytes. A real human cannot accidentally trigger this rule.
    no_behavior_at_all = (
        pointer_path_length == 0 and scroll_count == 0 and focus_events == 0
        and not parsed_dict["is_mobile"]
    )
    s = 0.0
    s += 35 if parsed_dict["is_bot"] else 0
    s += 30 if canvas_fabricated else 0
    s += 20 if audio_fabricated else 0
    s += 25 if no_behavior_at_all else 0
    s += 25 if webdriver_present else 0
    s += min(20, automation_flag_count * 5)
    s += 12 if webgl_known_bad else 0
    s += 10 if missing_chrome_runtime else 0
    s += 8 if plugins_count == 0 and not parsed_dict["is_mobile"] else 0
    s += 8 if fonts_detected < 5 and not parsed_dict["is_mobile"] else 0
    s += 6 if not webrtc_ip_leaked and not parsed_dict["is_mobile"] else 0
    s += 6 if pointer_path_length == 0 and not parsed_dict["is_mobile"] else 0
    s += 4 if not timezone_consistency else 0
    s += 4 if canvas_entropy < 10 else 0
    if no_behavior_at_all:
        flags.append(
            "No pointer, scroll, or focus events recorded on a desktop browser "
            "— a human had to interact with the widget to submit it"
        )
    suspicion_score = float(min(100.0, s))

    return TelemetrySummary(
        feature_vector=feature_vector,
        risk_flags=flags,
        fingerprint=fingerprint,
        parsed_ua=parsed_dict,
        raw=raw,
        suspicion_score=suspicion_score,
    )
