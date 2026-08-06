"""Grace-period / offline validation.

Boundary semantics are strict (``>``, never ``>=``). The 365-day "too old"
ceiling is an independent check that has nothing to do with the grace
period.
"""

from __future__ import annotations

from . import errors
from .domain import License

_MAX_AGE_SECS = 365 * 24 * 60 * 60
_MAX_RENEWAL_TIME_SECS = 60 * 60


def validate_at(license: License, machine_id: str, now: float) -> None:
    """Validates ``license`` against ``machine_id`` as of ``now`` (unix
    seconds). Raises a ``ValidateError`` subclass on rejection; returns
    ``None`` on success.
    """
    if license.issued_at == 0:
        raise errors.InvalidFieldsError("issued_at is zero")
    if license.expires_at == 0:
        raise errors.InvalidFieldsError("expires_at is zero")
    if license.grace_period_secs <= 0:
        raise errors.InvalidFieldsError("grace_period is zero or negative")
    if license.machine_id != machine_id:
        raise errors.MachineIdMismatchError()
    if license.expires_at < license.issued_at:
        raise errors.InvalidFieldsError("expires_at is before issued_at")

    # perpetual_fixed tokens never expire and have no grace-period check,
    # but the four preconditions above still apply unconditionally,
    # including grace_period > 0, even though it's otherwise unused for this
    # type. The checks run before the branch on license_type.
    if license.is_perpetual_fixed:
        if now > license.expires_at:
            raise errors.HardExpiredError()
        return

    offline_deadline = license.issued_at + license.grace_period_secs

    if now > license.expires_at:
        raise errors.HardExpiredError()
    if now > offline_deadline:
        raise errors.GraceExpiredError()
    if now - license.issued_at > _MAX_AGE_SECS:
        raise errors.LicenseTooOldError()


def in_grace_period(license: License, now: float) -> bool:
    """True once more than 60 minutes have passed since ``issued_at``
    without a renewal, while still inside the grace window measured from
    that same ``issued_at``. This is **not** "is the license in its grace
    period" despite the name: it flags a stale-but-not-yet-expired
    renewal, not general grace-period membership.
    """
    since_activation = now - license.issued_at
    return _MAX_RENEWAL_TIME_SECS < since_activation < license.grace_period_secs


def is_valid(license: License, now: float) -> bool:
    """``now - issued_at <= grace_period``, inclusive at the boundary. A
    third, distinct freshness check from ``validate_at``'s grace-deadline
    branch and from ``in_grace_period`` above; kept as a separate function
    rather than collapsed into one.
    """
    return (now - license.issued_at) <= license.grace_period_secs
