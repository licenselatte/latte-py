"""Domain types used across chain verification and license validation."""

from __future__ import annotations

from dataclasses import dataclass, field


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
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def is_perpetual_fixed(self) -> bool:
        return self.license_type == PERPETUAL_FIXED
