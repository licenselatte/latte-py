"""Domain types used across chain verification and license validation."""

from __future__ import annotations

from dataclasses import dataclass, field

from .entitlements import EntitlementValue


@dataclass(frozen=True)
class CertChain:
    """Master (implicit, caller-supplied) -> Submaster -> Project -> Daily."""

    submaster: str
    project: str
    daily: str


PERPETUAL_FIXED = "perpetual_fixed"
PERPETUAL = "perpetual"
EXPIRING = "expiring"


@dataclass
class License:
    """A chain-verified, not-yet-grace-validated license.

    Produced by ``verify.verify_activation_at``, consumed by
    ``validate.validate_at``.
    """

    key: str
    activation_id: str
    project_id: str
    machine_id: str
    issued_at: float  # unix seconds
    expires_at: float  # unix seconds
    grace_period_secs: float
    license_type: str
    #: The legacy-system key string this license was resolved from, when
    #: it was minted via a legacy-key migration alias rather than
    #: activated by its own native key. "" for a natively-keyed license.
    #: Internal only — used to recognize a cached token on a later
    #: activate() call passing the same legacy key, since `key` above
    #: will be the newly minted native key instead. See the JWT's "alias"
    #: claim.
    alias: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    #: The decoded ``ent`` claim, or ``None`` when the token carried no
    #: such claim at all -- a different thing from an empty mapping, and
    #: the distinction ``PublicLicense.has_entitlements`` reports. See
    #: ``latte.entitlements``.
    entitlements: dict[str, EntitlementValue] | None = None

    @property
    def is_perpetual_fixed(self) -> bool:
        return self.license_type == PERPETUAL_FIXED
