"""Trust-tier policy.

Three tiers — BASIC, STANDARD, PREMIUM — each with different lifetime,
reputation requirements, and identity-anchoring rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Tier(str, Enum):
    BASIC = "BASIC"
    STANDARD = "STANDARD"
    PREMIUM = "PREMIUM"


@dataclass(frozen=True)
class TierPolicy:
    name: Tier
    token_lifetime_seconds: int
    min_reputation: float
    requires_identity_link: bool
    description: str


POLICIES: dict[Tier, TierPolicy] = {
    Tier.BASIC: TierPolicy(
        name=Tier.BASIC,
        token_lifetime_seconds=24 * 3600,  # 24 hours, anonymous, rotates daily
        min_reputation=0.0,
        requires_identity_link=False,
        description=(
            "Free, fully anonymous. Suitable for comments, basic logins, and "
            "low-value access. Token rotates every 24 hours."
        ),
    ),
    Tier.STANDARD: TierPolicy(
        name=Tier.STANDARD,
        token_lifetime_seconds=30 * 24 * 3600,  # 30 days
        min_reputation=70.0,
        requires_identity_link=False,
        description=(
            "Pseudonymous reputation tier. Sites may store an aggregate "
            "abuse score, but no PII. Suitable for forums, marketplaces, "
            "moderated communities."
        ),
    ),
    Tier.PREMIUM: TierPolicy(
        name=Tier.PREMIUM,
        token_lifetime_seconds=180 * 24 * 3600,  # 180 days
        min_reputation=85.0,
        requires_identity_link=True,
        description=(
            "Opt-in identity-anchored tier. Links to Aadhaar / UPI / "
            "DigiLocker via salted hash; identity data never leaves the "
            "India-stack home jurisdiction. Required for banking, voting, "
            "and high-value transactions."
        ),
    ),
}


def policy_for(tier: Tier) -> TierPolicy:
    return POLICIES[tier]


def can_issue(tier: Tier, reputation_score: float, identity_linked: bool) -> tuple[bool, str]:
    p = policy_for(tier)
    if reputation_score < p.min_reputation:
        return False, (
            f"Reputation {reputation_score:.1f} below {tier.value} tier "
            f"minimum of {p.min_reputation:.1f}."
        )
    if p.requires_identity_link and not identity_linked:
        return False, f"{tier.value} tier requires an opt-in identity link."
    return True, "Eligible"
