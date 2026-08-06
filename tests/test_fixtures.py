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

TESTDATA = Path(__file__).parent.parent / "testdata"


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


def test_fixture_set_is_complete() -> None:
    assert len(_load_fixtures()) > 15
