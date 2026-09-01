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
from .domain import CertChain, License
from .entitlements import EntitlementValue, can, limit


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

    #: The typed feature map the seller signed into this licence: a flat
    #: mapping whose values are ``bool`` and ``int`` and nothing else.
    #: Read it with :meth:`can` and :meth:`limit` rather than subscripting
    #: it directly, unless you want to enumerate what was granted.
    #:
    #: Always a mapping -- empty when the token carried no ``ent`` claim.
    #: Use :attr:`has_entitlements` to tell those two cases apart. See
    #: ``latte.entitlements`` for the full contract.
    entitlements: dict[str, EntitlementValue] = field(default_factory=dict)

    #: Whether the activation token carried an ``ent`` claim at all --
    #: including an empty one, which is why this is not a ``len()`` check.
    #:
    #: It exists for one job: letting an application fall back to its
    #: pre-entitlements behaviour for the one release it takes an
    #: installed base to renew. Absence denies, so without this probe,
    #: shipping ``can()`` before setting values in the dashboard switches
    #: the feature off for every customer holding an older cached token.
    #:
    #: A plain field rather than a ``@property``: it reads identically at
    #: every call site (``lic.has_entitlements``, no parentheses) and
    #: keeps this dataclass constructible in one expression.
    has_entitlements: bool = False

    def can(self, key: str) -> bool:
        """Whether the boolean entitlement named by ``key`` is present and
        true.

        A key that is absent, or that holds an integer rather than a
        boolean, answers ``False``. There is no coercion across kinds:
        ``can`` on an integer entitlement is false even when that integer
        is non-zero.
        """
        return can(self.entitlements, key)

    def limit(self, key: str) -> int | None:
        """The integer entitlement named by ``key``, or ``None`` when it is
        absent.

        The unlimited sentinel is returned as-is: compare against
        ``latte.UNLIMITED`` rather than testing for a negative number.
        ``limit`` on a boolean entitlement is ``None``, not 1 or 0.
        """
        return limit(self.entitlements, key)


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

    return _to_public_license(lic, validate.in_grace_period(lic, now))


def _to_public_license(lic: License, in_grace: bool) -> PublicLicense:
    """Projects a chain-verified :class:`~latte.domain.License` onto its
    public shape.

    Shared with the cached-token path in ``http.py`` rather than inlined at
    each call site: the two used to be duplicate constructor calls, and a
    field added to one and not the other is a difference nothing would
    catch.
    """
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
        # Always a mapping, so callers can iterate unconditionally; the
        # absent-versus-empty distinction lives in has_entitlements alone.
        entitlements=lic.entitlements if lic.entitlements is not None else {},
        has_entitlements=lic.entitlements is not None,
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
