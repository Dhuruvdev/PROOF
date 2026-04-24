"""Behavioral DNA — feature extraction from raw human input timing.

The PROOF Protocol records *implicit* signals the user generates while
typing a short calibration phrase: dwell times, flight times, n-gram
timing entropy, micro-tremor amplitude in the 8–12 Hz band, and velocity
entropy. These features are device + human dependent and are extremely
difficult to reproduce in software without a real biological driver.

This module operates on raw event streams of the form

    [{"key": "h", "down": 1729000123.412, "up": 1729000123.498}, ...]

All times are in seconds (POSIX epoch or relative). The output is a
fixed-length feature vector ``BehavioralVector`` plus a single 256-bit
fingerprint suitable for use as the message of a Pedersen commitment.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

import numpy as np
from scipy.signal import welch


FEATURE_NAMES: tuple[str, ...] = (
    "dwell_mean",
    "dwell_std",
    "flight_mean",
    "flight_std",
    "typing_speed_cps",
    "rhythm_entropy",
    "velocity_entropy",
    "tremor_8_12hz_power",
    "tremor_band_ratio",
    "jitter_iqr",
)


# ---- Tunables ------------------------------------------------------------- #
MIN_EVENTS = 6
NUM_BUCKETS = 16          # bins for entropy estimation
TREMOR_LOW_HZ = 8.0
TREMOR_HIGH_HZ = 12.0
SAMPLE_RATE_HZ = 100.0    # resampling rate for spectral analysis
MATCH_THRESHOLD = 0.55    # cosine-distance ceiling for "same human-device" match


@dataclass(frozen=True)
class BehavioralVector:
    """A normalized feature vector + reproducible fingerprint."""

    features: tuple[float, ...]
    fingerprint: bytes  # 32 bytes — used as scalar input to commitments

    def as_array(self) -> np.ndarray:
        return np.asarray(self.features, dtype=np.float64)


@dataclass
class KeyEvent:
    key: str
    down: float
    up: float

    @property
    def dwell(self) -> float:
        return max(0.0, self.up - self.down)


def _shannon_entropy(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    arr = np.asarray(values, dtype=np.float64)
    if np.allclose(arr, arr[0]):
        return 0.0
    hist, _ = np.histogram(arr, bins=NUM_BUCKETS)
    p = hist[hist > 0] / hist.sum()
    return float(-(p * np.log2(p)).sum())


def _band_power(signal: np.ndarray, fs: float, lo: float, hi: float) -> tuple[float, float]:
    if signal.size < 8:
        return 0.0, 0.0
    nperseg = int(min(len(signal), max(8, fs)))
    freqs, psd = welch(signal - signal.mean(), fs=fs, nperseg=nperseg)
    if psd.sum() <= 0:
        return 0.0, 0.0
    band_mask = (freqs >= lo) & (freqs <= hi)
    band_power = float(psd[band_mask].sum())
    total_power = float(psd.sum())
    ratio = band_power / total_power if total_power > 0 else 0.0
    return band_power, ratio


def _resample_uniform(times: np.ndarray, values: np.ndarray, fs: float) -> np.ndarray:
    if times.size < 2:
        return values.copy()
    duration = times[-1] - times[0]
    if duration <= 0:
        return values.copy()
    n_samples = max(8, int(duration * fs))
    grid = np.linspace(times[0], times[-1], n_samples)
    return np.interp(grid, times, values)


def parse_events(raw: Iterable[dict]) -> List[KeyEvent]:
    events: List[KeyEvent] = []
    for r in raw:
        try:
            events.append(KeyEvent(key=str(r["key"]), down=float(r["down"]), up=float(r["up"])))
        except (KeyError, ValueError, TypeError):
            continue
    events.sort(key=lambda e: e.down)
    return events


def extract_features(raw_events: Iterable[dict]) -> BehavioralVector:
    """Compute the 10-dimensional feature vector + 32-byte fingerprint.

    Raises ``ValueError`` if there are fewer than ``MIN_EVENTS`` valid events.
    """
    events = parse_events(raw_events)
    if len(events) < MIN_EVENTS:
        raise ValueError(
            f"Need at least {MIN_EVENTS} key events for a behavioral capture; got {len(events)}"
        )

    dwells = np.array([e.dwell for e in events], dtype=np.float64)
    flights = np.array(
        [events[i + 1].down - events[i].up for i in range(len(events) - 1)],
        dtype=np.float64,
    )
    flights = np.clip(flights, a_min=-0.5, a_max=5.0)

    total_time = events[-1].up - events[0].down
    speed = (len(events) / total_time) if total_time > 0 else 0.0

    # Velocity = inverse of inter-keystroke interval, normalised
    intervals = np.diff([e.down for e in events])
    velocities = 1.0 / np.clip(intervals, a_min=1e-3, a_max=None)
    vel_entropy = _shannon_entropy(velocities.tolist())

    # Tremor estimation — analyse the dwell-time signal as a function of time.
    times = np.array([e.down - events[0].down for e in events], dtype=np.float64)
    resampled = _resample_uniform(times, dwells, SAMPLE_RATE_HZ)
    band_power, band_ratio = _band_power(resampled, SAMPLE_RATE_HZ, TREMOR_LOW_HZ, TREMOR_HIGH_HZ)

    # Inter-quartile range of flight-times = pure jitter measure.
    jitter_iqr = float(np.subtract(*np.percentile(flights, [75, 25]))) if flights.size else 0.0

    features = (
        float(dwells.mean()),
        float(dwells.std()),
        float(flights.mean()) if flights.size else 0.0,
        float(flights.std()) if flights.size else 0.0,
        float(speed),
        _shannon_entropy(np.diff([e.down for e in events]).tolist()),
        vel_entropy,
        band_power,
        band_ratio,
        jitter_iqr,
    )

    fingerprint = _fingerprint(features)
    return BehavioralVector(features=features, fingerprint=fingerprint)


def _fingerprint(features: tuple[float, ...]) -> bytes:
    """Produce a 32-byte digest stable across small numerical noise."""
    # Quantize to 4 decimal places before hashing so two captures of the
    # same human on the same device map to the same fingerprint when
    # features round identically.
    quantized = ",".join(f"{v:.4f}" for v in features)
    return hashlib.sha256(quantized.encode("utf-8")).digest()


def cosine_distance(a: BehavioralVector, b: BehavioralVector) -> float:
    va, vb = a.as_array(), b.as_array()
    na = np.linalg.norm(va)
    nb = np.linalg.norm(vb)
    if na == 0 or nb == 0:
        return 1.0
    cos_sim = float(np.dot(va, vb) / (na * nb))
    return 1.0 - cos_sim


def matches(reference: BehavioralVector, candidate: BehavioralVector) -> tuple[bool, float]:
    """Return (is_match, distance) using cosine distance against the threshold."""
    d = cosine_distance(reference, candidate)
    return d <= MATCH_THRESHOLD, d
