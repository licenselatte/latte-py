"""Runs every shared fixture in testdata/ against this package's
verify/validate pipeline. See ../../latte-testvectors/README.md for the
fixture schema and the expect_reason taxonomy this test asserts against.
"""

from __future__ import annotations

import calendar
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from latte import errors, validate, verify
from latte.domain import CertChain
from latte.entitlements import UNLIMITED
from latte.license import PublicLicense, _to_public_license

TESTDATA = Path(__file__).parent.parent / "testdata" / "vectors"


def _load_fixtures() -> list[dict]:
    fixtures = []
    for path in sorted(TESTDATA.glob("*.json")):
        if path.name == "manifest.json":
            continue
        fixtures.append(json.loads(path.read_text()))
    return fixtures


def _parse_rfc3339(s: str) -> float:
    assert s.endswith("Z"), f"fixture 'now' must be UTC: {s}"
    t = time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    return float(calendar.timegm(t))


_REASON_MAP = {
    errors.HardExpiredError: "hard_expired",
    errors.GraceExpiredError: "grace_expired",
    errors.LicenseTooOldError: "license_too_old",
    errors.MachineIdMismatchError: "machine_id_mismatch",
    errors.InvalidFieldsError: "other",
}


def _reason_for(exc: errors.ValidateError) -> str:
    return _REASON_MAP.get(type(exc), "other")


@pytest.mark.parametrize("fixture", _load_fixtures(), ids=lambda f: f["name"])
def test_fixture(fixture: dict) -> None:
    now = _parse_rfc3339(fixture["now"])
    master_pub = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(fixture["master_public_key_hex"])
    )
    chain = CertChain(
        submaster=fixture["chain"]["submaster"],
        project=fixture["chain"]["project"],
        daily=fixture["chain"]["daily"],
    )

    try:
        lic = verify.verify_activation_at(master_pub, fixture["token"], chain, now)
    except errors.VerifyError:
        assert fixture["expect"] == "reject" and fixture["expect_stage"] == "verify", (
            f"unexpected verify-stage rejection for {fixture['name']}"
        )
        return

    assert not (fixture["expect"] == "reject" and fixture["expect_stage"] == "verify"), (
        f"expected verify-stage rejection for {fixture['name']} but chain verified"
    )

    try:
        validate.validate_at(lic, fixture["machine_id"], now)
    except errors.ValidateError as e:
        assert fixture["expect"] == "reject" and fixture["expect_stage"] == "validate", (
            f"unexpected validate-stage rejection for {fixture['name']}: {e}"
        )
        assert _reason_for(e) == fixture["expect_reason"], (
            f"reason mismatch for {fixture['name']}: got {_reason_for(e)}, "
            f"want {fixture['expect_reason']}"
        )
        return

    assert fixture["expect"] == "accept", (
        f"expected rejection for {fixture['name']} but verify+validate both succeeded"
    )

    in_grace = validate.in_grace_period(lic, now)
    assert in_grace == fixture["expect_in_grace_period"], (
        f"in_grace_period mismatch for {fixture['name']}: got {in_grace}, "
        f"want {fixture['expect_in_grace_period']}"
    )

    # Through _to_public_license rather than the decoder directly, so this
    # covers the wiring an application actually gets back from activate()
    # and check(), not just the parsing.
    _assert_entitlements(_to_public_license(lic, in_grace), fixture)


def _assert_entitlements(lic: PublicLicense, fixture: dict) -> None:
    """Checks the shared entitlement contract from
    latte-testvectors/README.md against one fixture.

    It asserts the *accessors*, not just the mapping, because the mapping
    is the easy half: the rules that actually split implementations are the
    ones about input an SDK does not like -- a malformed value that must be
    dropped rather than raised on, and the two coercions (a falsy 0, a
    boolean read as 1) that must miss rather than convert.
    """
    name = fixture["name"]

    assert lic.has_entitlements == fixture["expect_has_entitlements"], (
        f"has_entitlements mismatch for {name}"
    )
    assert lic.entitlements == fixture["expect_entitlements"], (
        f"entitlements mismatch for {name}: got {lic.entitlements}, "
        f"want {fixture['expect_entitlements']}"
    )

    for key, want in fixture["expect_entitlements"].items():
        # bool before int: in Python bool is an int subclass, so the
        # obvious isinstance(want, int) would swallow every boolean and
        # test the wrong accessor.
        if isinstance(want, bool):
            assert lic.can(key) is want, f"can({key!r}) mismatch for {name}"
            # No coercion: a boolean is not 1 or 0.
            assert lic.limit(key) is None, (
                f"limit({key!r}) on a boolean entitlement must miss, in {name}"
            )
        else:
            assert lic.limit(key) == want, f"limit({key!r}) mismatch for {name}"
            if want == UNLIMITED:
                assert lic.limit(key) == UNLIMITED, (
                    f"limit({key!r}) must return the UNLIMITED sentinel as-is, in {name}"
                )
            # No coercion: an integer is not truthy, not even a non-zero one.
            assert lic.can(key) is False, (
                f"can({key!r}) on an integer entitlement must be False, in {name}"
            )

    # Absence denies, whether or not the claim was there at all.
    assert lic.can("no_such_entitlement_key") is False
    assert lic.limit("no_such_entitlement_key") is None


def test_fixture_set_is_complete() -> None:
    assert len(_load_fixtures()) > 15
