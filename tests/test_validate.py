"""Isolated grace-period math tests: boundary conditions (exactly at the
threshold, one second before, one second after) and the independent checks
that make up validate.validate_at. No signing involved: pure arithmetic
over synthetic License objects.
"""

from __future__ import annotations

import pytest

from latte import errors, validate
from latte.domain import EXPIRING, PERPETUAL_FIXED, License

DAY = 24 * 60 * 60
NOW_ANCHOR = 10_000_000.0


def make_license(**overrides) -> License:
    base = dict(
        key="K",
        activation_id="A",
        project_id="P",
        machine_id="M",
        issued_at=NOW_ANCHOR - 7 * DAY,
        expires_at=NOW_ANCHOR + 365 * DAY,
        grace_period_secs=7 * DAY,
        license_type=EXPIRING,
        metadata={},
    )
    base.update(overrides)
    return License(**base)


def test_grace_boundary_exact_deadline_is_still_valid():
    lic = make_license()
    deadline = lic.issued_at + lic.grace_period_secs
    validate.validate_at(lic, "M", deadline)  # no raise


def test_grace_boundary_one_second_before_is_valid():
    lic = make_license()
    deadline = lic.issued_at + lic.grace_period_secs - 1
    validate.validate_at(lic, "M", deadline)  # no raise


def test_grace_boundary_one_second_after_is_grace_expired():
    lic = make_license()
    deadline = lic.issued_at + lic.grace_period_secs + 1
    with pytest.raises(errors.GraceExpiredError):
        validate.validate_at(lic, "M", deadline)


def test_hard_expiry_wins_even_within_nominal_grace_window():
    lic = make_license(expires_at=NOW_ANCHOR - 7 * DAY + 3600)
    check_at = lic.expires_at + 1
    with pytest.raises(errors.HardExpiredError):
        validate.validate_at(lic, "M", check_at)


def test_license_too_old_fires_independent_of_grace_and_expiry():
    lic = make_license(grace_period_secs=1000 * DAY, expires_at=NOW_ANCHOR + 2000 * DAY)
    check_at = lic.issued_at + 366 * DAY
    with pytest.raises(errors.LicenseTooOldError):
        validate.validate_at(lic, "M", check_at)


def test_machine_id_mismatch():
    lic = make_license()
    with pytest.raises(errors.MachineIdMismatchError):
        validate.validate_at(lic, "someone-else", NOW_ANCHOR)


def test_perpetual_fixed_still_requires_positive_grace_period():
    lic = make_license(license_type=PERPETUAL_FIXED, grace_period_secs=0)
    with pytest.raises(errors.InvalidFieldsError):
        validate.validate_at(lic, "M", NOW_ANCHOR)


def test_perpetual_fixed_skips_grace_deadline_but_not_hard_expiry():
    lic = make_license(license_type=PERPETUAL_FIXED)
    check_at = lic.issued_at + lic.grace_period_secs + 1
    validate.validate_at(lic, "M", check_at)  # no raise: no grace check for this type


def test_perpetual_fixed_still_hard_expires():
    lic = make_license(license_type=PERPETUAL_FIXED, expires_at=NOW_ANCHOR - 1)
    with pytest.raises(errors.HardExpiredError):
        validate.validate_at(lic, "M", NOW_ANCHOR)


def test_in_grace_period_false_before_60_minute_marker():
    lic = make_license(issued_at=NOW_ANCHOR - 30 * 60)
    assert not validate.in_grace_period(lic, NOW_ANCHOR)


def test_in_grace_period_true_between_60_minutes_and_deadline():
    lic = make_license(issued_at=NOW_ANCHOR - 2 * 60 * 60)
    assert validate.in_grace_period(lic, NOW_ANCHOR)


def test_is_valid_matches_boundary():
    lic = make_license()
    deadline = lic.issued_at + lic.grace_period_secs
    assert validate.is_valid(lic, deadline)
    assert not validate.is_valid(lic, deadline + 1)


@pytest.mark.parametrize(
    "field,value",
    [("issued_at", 0), ("expires_at", 0), ("grace_period_secs", 0)],
)
def test_invalid_fields_rejected(field, value):
    lic = make_license(**{field: value})
    with pytest.raises(errors.InvalidFieldsError):
        validate.validate_at(lic, "M", NOW_ANCHOR)


def test_expires_before_issued_rejected():
    lic = make_license(expires_at=NOW_ANCHOR - 8 * DAY)  # before issued_at
    with pytest.raises(errors.InvalidFieldsError):
        validate.validate_at(lic, "M", NOW_ANCHOR)
