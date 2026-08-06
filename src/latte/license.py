"""The verified, validated, "safe to use" view of a license, and the
pipeline that produces it.

Split out of ``__init__.py`` (which re-exports everything here unchanged)
so that ``latte.http`` can depend on ``check_license_at``/``PublicLicense``
without a circular import through the package ``__init__``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import validate, verify
from .domain import CertChain


@dataclass
class PublicLicense:
    """The verified, validated, "safe to use" view of a license."""

    key: str
    activation_id: str
    project_id: str
    issued_at: float
    expires_at: float
    grace_period_secs: float
    in_grace_period: bool
    license_type: str
    metadata: dict[str, str] = field(default_factory=dict)


def check_license_at(
    master_pub: Ed25519PublicKey,
    token: str,
    chain: CertChain,
    machine_id: str,
    now: float,
) -> PublicLicense:
    """Runs the full verification pipeline on every cached token: chain
    verification, then grace-period validation, then the in-grace-period
    computation.

    Raises a ``VerifyError`` subclass if the chain/signature doesn't check
    out, or a ``ValidateError`` subclass if it checks out but is expired /
    out of grace / for the wrong machine. This is the primary entry point
    plugin developers embed: see README.md for usage.
    """
    lic = verify.verify_activation_at(master_pub, token, chain, now)
    validate.validate_at(lic, machine_id, now)
    in_grace = validate.in_grace_period(lic, now)

    return PublicLicense(
        key=lic.key,
        activation_id=lic.activation_id,
        project_id=lic.project_id,
        issued_at=lic.issued_at,
        expires_at=lic.expires_at,
        grace_period_secs=lic.grace_period_secs,
        in_grace_period=in_grace,
        license_type=lic.license_type,
        metadata=lic.metadata,
    )


def check_license(
    master_pub: Ed25519PublicKey,
    token: str,
    chain: CertChain,
    machine_id: str,
) -> PublicLicense:
    """``check_license_at`` using the real system clock. See that function's
    docstring for details.
    """
    return check_license_at(master_pub, token, chain, machine_id, time.time())
