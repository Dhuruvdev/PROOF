"""Risk engine — combines all signals into a single decision.

Inputs (all real, all already validated by the relevant layer):

* PoW: did the client solve the silent proof-of-work?
* Telemetry: rule-based suspicion score + IsolationForest anomaly score
* Behavioral DNA: cosine distance to enrolled vector
* Reputation: device's running score
* Token freshness: how old is the issued token
* Replay: has this nonce been seen before?

Outputs:

* RiskDecision.action ∈ {ALLOW, ALLOW_WITH_INTERACTION, CHALLENGE, BLOCK}
  — exactly the four-path Cloudflare Challenge Platform pattern.
* RiskDecision.score: 0 (clean human) … 100 (almost certainly bot)
* RiskDecision.reasons: human-readable contributors
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import numpy as np
from sklearn.ensemble import IsolationForest

from .telemetry import FEATURE_LAYOUT, TelemetrySummary


class Action(str, Enum):
    ALLOW = "ALLOW"                                # silent, fast path
    ALLOW_WITH_INTERACTION = "ALLOW_WITH_INTERACTION"  # checkbox slow path
    CHALLENGE = "CHALLENGE"                        # additional ZK / behavioral re-capture
    BLOCK = "BLOCK"                                # hard reject


@dataclass
class RiskDecision:
    score: float                              # 0 (human) … 100 (bot)
    action: Action
    reasons: list[str] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)
    fast_path_eligible: bool = False

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "action": self.action.value,
            "reasons": list(self.reasons),
            "components": dict(self.components),
            "fast_path_eligible": self.fast_path_eligible,
        }


# --------------------------------------------------------------------------- #
# Anomaly model
# --------------------------------------------------------------------------- #


def _human_training_set(rng: np.random.Generator, n: int = 600) -> np.ndarray:
    """Generate a population of plausible *human* feature vectors.

    The population is intentionally diverse: desktop, laptop, mobile, tablet,
    Linux/Mac/Windows, modern + slightly older browsers. This is what the
    IsolationForest will treat as "normal".
    """
    rows = []
    for _ in range(n):
        is_mobile = rng.random() < 0.45
        rows.append([
            0.0,                                             # ua_is_known_bot
            float(rng.integers(0, 1)),                       # automation flags
            0.0,                                             # webdriver
            0.0,                                             # missing chrome runtime
            float(rng.integers(0, 6) if not is_mobile else rng.integers(0, 3)),  # plugins
            float(rng.integers(1, 5)),                       # languages
            float(rng.integers(15, 80) if not is_mobile else rng.integers(8, 30)),  # fonts
            float(rng.integers(2, 16)),                      # hwc
            float(rng.choice([0.5, 1, 2, 4, 8])),            # device memory
            float(rng.integers(300, 8200)),                  # screen kpx
            1.0,                                             # tz consistency
            float(rng.uniform(20, 90)),                      # canvas entropy
            0.0,                                             # webgl bad
            float(rng.uniform(15, 45)),                      # audio entropy
            float(rng.integers(0, 2)),                       # webrtc leaked
            float(rng.integers(0, 2)),                       # local private ip
            float(rng.uniform(8, 80)),                       # pointer jitter ms
            float(rng.integers(20, 400) if not is_mobile else rng.integers(0, 50)),
            float(rng.integers(0, 30)),                      # scroll
            float(rng.integers(0, 8)),                       # focus events
            float(rng.integers(80, 500)),                    # solve ms
            float(rng.uniform(0, 4)),                        # ua age
            1.0 if is_mobile else 0.0,
            1.0 if is_mobile or rng.random() < 0.1 else 0.0, # is_touch
            float(rng.integers(0, 2)),                       # battery
            float(rng.integers(20, 250)),                    # rtt
            float(rng.uniform(0.2, 6.0)),                    # request age s
        ])
    return np.asarray(rows, dtype=np.float64)


class _AnomalyModel:
    """Lazy-trained IsolationForest. One process-wide instance."""

    _instance: "IsolationForest | None" = None

    @classmethod
    def get(cls) -> IsolationForest:
        if cls._instance is None:
            rng = np.random.default_rng(seed=20260424)
            X = _human_training_set(rng)
            model = IsolationForest(
                n_estimators=200,
                contamination=0.05,
                random_state=20260424,
            )
            model.fit(X)
            cls._instance = model
        return cls._instance


def anomaly_score(features: list[float]) -> float:
    """Return a 0..100 anomaly score (higher = more anomalous vs. humans)."""
    arr = np.asarray(features, dtype=np.float64).reshape(1, -1)
    if arr.shape[1] != len(FEATURE_LAYOUT):
        return 50.0
    model = _AnomalyModel.get()
    # decision_function: positive = inlier, negative = outlier
    raw = float(model.decision_function(arr)[0])
    # Empirical bounds on the training distribution: clamp -0.3..+0.3 → 100..0
    score = max(0.0, min(100.0, (0.3 - raw) / 0.6 * 100.0))
    return score


# --------------------------------------------------------------------------- #
# Top-level decision
# --------------------------------------------------------------------------- #


def evaluate(
    telemetry: TelemetrySummary,
    pow_solved: bool,
    pow_elapsed_ms: float,
    behavioral_distance: float | None,
    reputation_score: float,
    replay_seen_before: bool,
    relying_party_min_action: Action = Action.ALLOW,
) -> RiskDecision:
    reasons: list[str] = []
    components: dict[str, float] = {}

    rule_score = telemetry.suspicion_score
    components["telemetry_rules"] = rule_score
    if rule_score > 0:
        reasons.extend(telemetry.risk_flags[:8])

    ml_score = anomaly_score(telemetry.feature_vector)
    components["telemetry_anomaly"] = ml_score
    if ml_score > 60:
        reasons.append(f"ML anomaly score {ml_score:.0f}/100 — fingerprint outside normal human distribution")

    # PoW contribution
    if pow_solved:
        components["pow"] = 0.0
        if pow_elapsed_ms < 5:
            components["pow"] = 35.0
            reasons.append(f"Proof-of-work solved in {pow_elapsed_ms:.0f} ms — implausibly fast for a real browser")
    else:
        components["pow"] = 60.0
        reasons.append("Proof-of-work was not solved")

    # Behavioral contribution (only when a token / enrollment exists)
    if behavioral_distance is not None:
        if behavioral_distance > 0.6:
            components["behavior"] = 70.0
            reasons.append(f"Behavioral capture far from enrolled profile (cosine distance {behavioral_distance:.2f})")
        elif behavioral_distance > 0.4:
            components["behavior"] = 30.0
            reasons.append(f"Behavioral capture loosely matches enrolled profile (distance {behavioral_distance:.2f})")
        else:
            components["behavior"] = 0.0
    else:
        components["behavior"] = 0.0

    components["reputation"] = max(0.0, 100.0 - reputation_score)

    if replay_seen_before:
        components["replay"] = 100.0
        reasons.append("Replay detected — challenge nonce was already used")
    else:
        components["replay"] = 0.0

    # Weighted sum.
    # Telemetry-rules dominates because each flag is a deterministic, high-
    # confidence "this is not a real browser" signal (matching how Cloudflare
    # weights browser-environment integrity above ML in their public docs).
    # PoW carries the next largest weight because it's binary and unforgeable.
    weights = {
        "telemetry_rules": 0.30,
        "telemetry_anomaly": 0.15,
        "pow": 0.20,
        "behavior": 0.15,
        "reputation": 0.10,
        "replay": 0.10,
    }
    # When behavioral signal is absent (the visitor never enrolled) redistribute
    # its weight to the other signals proportionally so we don't penalise the
    # honest visitor for a missing optional input.
    if behavioral_distance is None:
        bw = weights.pop("behavior")
        total = sum(weights.values())
        for k in weights:
            weights[k] = weights[k] * (1.0 + bw / total)
        components["behavior"] = 0.0
    score = sum(components[k] * weights[k] for k in weights)
    score = float(max(0.0, min(100.0, score)))

    # Decision thresholds (mirrors the Cloudflare fast/slow/challenge model).
    # Hard overrides: when a single signal is overwhelming we don't let the
    # weighted average dilute it. This mirrors the rule "if the browser self-
    # identifies as HeadlessChrome with webdriver=true and SwiftShader GPU,
    # no amount of mouse movement saves you".
    rule_score = components.get("telemetry_rules", 0.0)
    if components["replay"] > 0:
        action = Action.BLOCK
    elif rule_score >= 80:
        action = Action.BLOCK
    elif score >= 75:
        action = Action.BLOCK
    elif score >= 55 or rule_score >= 50:
        action = Action.CHALLENGE
    elif score >= 30:
        action = Action.ALLOW_WITH_INTERACTION
    else:
        action = Action.ALLOW

    # Honour the relying party's minimum required action
    order = [Action.ALLOW, Action.ALLOW_WITH_INTERACTION, Action.CHALLENGE, Action.BLOCK]
    if order.index(action) < order.index(relying_party_min_action):
        action = relying_party_min_action

    fast = action == Action.ALLOW
    return RiskDecision(
        score=score,
        action=action,
        reasons=reasons,
        components=components,
        fast_path_eligible=fast,
    )
