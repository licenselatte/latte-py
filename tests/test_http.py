"""Tests for `Sdk.activate`/`Sdk.renew`/`Sdk.check` and the machine calls
(`deactivate`/`machines`/`rename_machine`) against a mocked
LicenseLatte API (`responses`), covering:
  - the exact wire request shape for activate/renew
  - status-code -> sentinel error mapping
  - transport-level failure -> NetworkError
  - malformed/empty response bodies -> ServerError
  - bad license-key format short-circuiting before any network call
  - the on-disk cache: falling through when it's unreadable/unverifiable,
    not writing a token that failed verification, and clearing it when the
    server says the activation no longer exists

What this file deliberately does *not* test: a full activate() success path
returning a real PublicLicense, or check()'s success/expired branches. Sdk
verifies against the hardcoded production master public key; the matching
private key lives only on LicenseLatte's real backend, so nothing in this
repo can produce a token this package would actually accept. The crypto
pipeline itself (check_license_at and everything it calls) is already
exhaustively covered by tests/test_fixtures.py against real (test) key
material: this file only needs to prove the network/cache plumbing
correctly feeds a syntactically-valid response into that pipeline, which
the "server-returned token fails verification" test below confirms end to
end (it just can't also assert *acceptance*, for the reason above).
tests/test_storage.py's own tests separately cover the cache file
format/atomicity in isolation, with no key material involved at all.
"""

from __future__ import annotations

import calendar
import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
import responses
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import latte
from latte import errors, machineid, storage
from latte.domain import CertChain
from latte.http import Config, Sdk

# A valid AppID (pk_test_{28-char data}{4-char checksum}) and a matching
# license key ({6-char short_id}{22 random}{2-char checksum}), computed
# against the checksum algorithm in latte/key.py.
TEST_APP_ID = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS"
TEST_LICENSE_KEY = "AHAK85BCDEFGHJKMNPQRSTVWXYZ00Z"
TEST_MACHINE_ID = "test-machine-id"
TEST_DERIVED_MACHINE_ID = machineid.protected_id(TEST_MACHINE_ID, TEST_APP_ID)
BASE_URL = "https://mock.invalid"

# Every activate/renew request names the SDK and the version sending it.
SDK_INFO = {"language": "python", "version": latte.__version__}


def make_sdk(cache_path: Path, machine_name: str | None = "") -> Sdk:
    return Sdk(
        Config(
            app_id=TEST_APP_ID,
            machine_id=TEST_MACHINE_ID,
            base_url=BASE_URL,
            cache_path=cache_path,
            machine_name=machine_name,
        )
    )


def garbage_chain() -> CertChain:
    return CertChain(submaster="s", project="p", daily="d")


@responses.activate
def test_activate_sends_the_documented_request_shape(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        },
        status=200,
        match=[
            responses.matchers.json_params_matcher(
                {
                    "project_key": TEST_APP_ID,
                    "license_key": TEST_LICENSE_KEY,
                    "machine_id": TEST_DERIVED_MACHINE_ID,
                    "sdk": SDK_INFO,
                }
            )
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError):
        sdk.activate(TEST_LICENSE_KEY)


@responses.activate
def test_renew_sends_the_documented_request_shape_without_project_key(tmp_path: Path) -> None:
    activation_id = "11111111-1111-1111-1111-111111111111"
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/renew",
        json={
            "token": "not-a-real-jwt",
            "activation_id": activation_id,
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        },
        status=200,
        match=[
            responses.matchers.json_params_matcher(
                {
                    "activation_id": activation_id,
                    "license_key": TEST_LICENSE_KEY,
                    "machine_id": TEST_DERIVED_MACHINE_ID,
                    "sdk": SDK_INFO,
                }
            )
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError):
        sdk.renew(activation_id, TEST_LICENSE_KEY)


@responses.activate
def test_server_returned_token_that_fails_verification_is_a_server_error(
    tmp_path: Path,
) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        },
        status=200,
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError, match="^server returned invalid token:"):
        sdk.activate(TEST_LICENSE_KEY)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (404, errors.LicenseNotFoundError),
        (403, errors.LicenseExpiredError),
        (409, errors.SeatLimitError),
        (401, errors.InvalidProjectKeyError),
    ],
)
@responses.activate
def test_status_codes_map_to_the_documented_sentinels(
    status: int, expected: type[Exception], tmp_path: Path
) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={"error": "nope"},
        status=status,
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(expected):
        sdk.activate(TEST_LICENSE_KEY)


@responses.activate
def test_unmapped_status_code_is_a_server_error_with_the_server_message(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={"error": "something broke"},
        status=500,
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError, match="^something broke$"):
        sdk.activate(TEST_LICENSE_KEY)


@responses.activate
def test_empty_token_in_a_200_response_is_a_server_error(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={
            "token": "",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        },
        status=200,
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError, match="^server returned empty token$"):
        sdk.activate(TEST_LICENSE_KEY)


@responses.activate
def test_transport_failure_is_a_network_error(tmp_path: Path) -> None:
    # No responses.add() registered for this URL, so `responses` raises a
    # ConnectionError for it, simulating a request that never got a
    # response (DNS/TCP/timeout).
    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.NetworkError):
        sdk.activate(TEST_LICENSE_KEY)


def test_empty_license_key_never_reaches_the_network(tmp_path: Path) -> None:
    # No @responses.activate at all: if activate() incorrectly made a
    # network call here, `requests` would try a real DNS lookup against
    # "mock.invalid" and fail loudly, so this test would fail either way a
    # bug could manifest.
    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.InvalidKeyError):
        sdk.activate("")


@responses.activate
def test_non_native_format_key_reaches_the_network_instead_of_being_rejected_locally(
    tmp_path: Path,
) -> None:
    # Doesn't match this project's short_id and fails the checksum -- the
    # strict format gate used to reject this before ever calling the
    # network. Now the server is the sole arbiter of native vs.
    # legacy-alias vs. not-found, so it must reach the network unchanged
    # (normalized only: uppercased, separators stripped).
    legacy_key = "acme-legacy-2019-key"
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        },
        status=200,
        match=[
            responses.matchers.json_params_matcher(
                {
                    "project_key": TEST_APP_ID,
                    "license_key": "ACMELEGACY2019KEY",
                    "machine_id": TEST_DERIVED_MACHINE_ID,
                    "sdk": SDK_INFO,
                }
            )
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError):
        sdk.activate(legacy_key)


# --- cache ---


def test_check_reports_not_activated_when_nothing_is_cached(tmp_path: Path) -> None:
    sdk = Sdk(
        Config(app_id=TEST_APP_ID, machine_id=TEST_MACHINE_ID, cache_path=tmp_path / "cache.json")
    )
    with pytest.raises(errors.NotActivatedError):
        sdk.check()


def test_check_reports_not_activated_when_caching_is_disabled(tmp_path: Path) -> None:
    sdk = Sdk(
        Config(
            app_id=TEST_APP_ID,
            machine_id=TEST_MACHINE_ID,
            cache=False,
            cache_path=tmp_path / "cache.json",
        )
    )
    with pytest.raises(errors.NotActivatedError):
        sdk.check()


def test_check_reports_not_activated_for_a_cache_that_fails_verification(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())

    sdk = Sdk(Config(app_id=TEST_APP_ID, machine_id=TEST_MACHINE_ID, cache_path=cache_path))
    with pytest.raises(errors.NotActivatedError):
        sdk.check()


@responses.activate
def test_activate_falls_through_to_the_network_when_the_cache_is_unverifiable(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(responses.POST, f"{BASE_URL}/v1/activate", status=404)

    sdk = make_sdk(cache_path)
    # LicenseNotFound only happens on the network path: reaching it proves
    # the unverifiable cache entry didn't short-circuit into a false
    # "success" or a cache-specific error.
    with pytest.raises(errors.LicenseNotFoundError):
        sdk.activate(TEST_LICENSE_KEY)


@responses.activate
def test_activate_does_not_cache_a_server_response_that_fails_verification(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "cache.json"
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        json={
            "token": "not-a-real-jwt",
            "activation_id": "11111111-1111-1111-1111-111111111111",
            "chain": {"submaster": "s", "project": "p", "daily": "d"},
        },
        status=200,
    )

    sdk = make_sdk(cache_path)
    with pytest.raises(errors.ServerError):
        sdk.activate(TEST_LICENSE_KEY)

    assert storage.load(cache_path) is None


@responses.activate
def test_activate_clears_an_existing_cache_entry_on_license_not_found(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(responses.POST, f"{BASE_URL}/v1/activate", status=404)

    sdk = make_sdk(cache_path)
    with pytest.raises(errors.LicenseNotFoundError):
        sdk.activate(TEST_LICENSE_KEY)

    assert storage.load(cache_path) is None


@responses.activate
def test_renew_clears_an_existing_cache_entry_on_license_expired(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(responses.POST, f"{BASE_URL}/v1/renew", status=403)

    sdk = make_sdk(cache_path)
    activation_id = "11111111-1111-1111-1111-111111111111"
    with pytest.raises(errors.LicenseExpiredError):
        sdk.renew(activation_id, TEST_LICENSE_KEY)

    assert storage.load(cache_path) is None


@responses.activate
def test_activate_leaves_an_existing_cache_entry_alone_on_an_unrelated_server_error(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(responses.POST, f"{BASE_URL}/v1/activate", status=500)

    sdk = make_sdk(cache_path)
    with pytest.raises(errors.ServerError):
        sdk.activate(TEST_LICENSE_KEY)

    # A 500 doesn't mean the activation is gone, just that something else
    # went wrong: an existing cache entry (unverifiable or not) shouldn't
    # be touched over it.
    assert cache_path.exists()


# --- machine calls ---

ACTIVATION_ID = "11111111-1111-1111-1111-111111111111"
CREDENTIALS = {
    "activation_id": ACTIVATION_ID,
    "license_key": TEST_LICENSE_KEY,
    "machine_id": TEST_DERIVED_MACHINE_ID,
    "sdk": SDK_INFO,
}


def activated_sdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Sdk, Path]:
    """An Sdk whose cache holds a licence ``check`` accepts: a shared test
    vector, with the SDK's master key, machine ID and clock set to the
    vector's."""
    vector = json.loads(
        (Path(__file__).parent.parent / "testdata/vectors/entitlements_absent.json").read_text()
    )
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, vector["token"], CertChain(**vector["chain"]))
    sdk = make_sdk(cache_path)
    sdk._master_pub = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vector["master_public_key_hex"])
    )
    sdk._machine_id = vector["machine_id"]
    now = calendar.timegm(time.strptime(vector["now"], "%Y-%m-%dT%H:%M:%SZ"))
    monkeypatch.setattr(latte.http, "time", SimpleNamespace(time=lambda: float(now)))
    sdk.check()
    return sdk, cache_path


@responses.activate
def test_deactivate_sends_renews_credentials_and_forgets_the_token(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/deactivate",
        json={"released": True, "seat_free_at": "2026-10-21T09:00:00Z"},
        match=[responses.matchers.json_params_matcher(CREDENTIALS)],
    )

    res = make_sdk(cache_path).deactivate(ACTIVATION_ID, TEST_LICENSE_KEY)

    assert res == latte.DeactivateResult(released=True, seat_free_at=1792573200.0)
    assert storage.load(cache_path) is None


@pytest.mark.parametrize("released", [True, False])
@responses.activate
def test_deactivate_success_makes_check_report_not_activated(
    released: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _ = activated_sdk(tmp_path, monkeypatch)
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/deactivate",
        json={"released": released, "seat_free_at": None},
    )

    res = sdk.deactivate(ACTIVATION_ID, TEST_LICENSE_KEY)

    assert res == latte.DeactivateResult(released=released, seat_free_at=None)
    with pytest.raises(errors.NotActivatedError):
        sdk.check()


@responses.activate
def test_deactivate_network_failure_keeps_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _ = activated_sdk(tmp_path, monkeypatch)

    with pytest.raises(errors.NetworkError):
        sdk.deactivate(ACTIVATION_ID, TEST_LICENSE_KEY)

    sdk.check()


@responses.activate
def test_deactivate_policy_refusal_keeps_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _ = activated_sdk(tmp_path, monkeypatch)
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/deactivate",
        json={
            "error": "Wait a week.",
            "reason": "deactivation_cooldown",
            "available_at": "2026-10-21T09:00:00Z",
        },
        status=409,
    )

    with pytest.raises(latte.DeactivationBlockedError) as exc:
        sdk.deactivate(ACTIVATION_ID, TEST_LICENSE_KEY)

    assert str(exc.value) == "Wait a week."
    assert exc.value.reason == "deactivation_cooldown"
    assert exc.value.available_at == 1792573200.0
    sdk.check()


@responses.activate
def test_deactivate_inactive_license_keeps_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _ = activated_sdk(tmp_path, monkeypatch)
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/deactivate",
        json={"error": "license is inactive or expired", "reason": "license_suspended"},
        status=403,
    )

    with pytest.raises(errors.LicenseExpiredError):
        sdk.deactivate(ACTIVATION_ID, TEST_LICENSE_KEY)

    sdk.check()


@responses.activate
def test_machines_parses_the_list(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/machines",
        json={
            "machines": [
                {
                    "machine_name": "Studio",
                    "machine_fingerprint": "9f1c4a0b2d3e",
                    "activated_at": "2026-10-01T00:00:00Z",
                    "last_seen_at": "2026-10-14T00:00:00.123456789Z",
                    "current": True,
                },
                {
                    "machine_fingerprint": "0a1b2c3d4e5f",
                    "activated_at": "2026-09-01T00:00:00Z",
                    "last_seen_at": "2026-09-02T00:00:00.5+02:00",
                    "seat_free_at": "2026-10-20T00:00:00Z",
                    "current": False,
                },
            ]
        },
        match=[responses.matchers.json_params_matcher(CREDENTIALS)],
    )

    machines = make_sdk(tmp_path / "cache.json").machines(ACTIVATION_ID, TEST_LICENSE_KEY)

    assert machines == [
        latte.Machine(
            name="Studio",
            fingerprint="9f1c4a0b2d3e",
            activated_at=1790812800.0,
            last_seen_at=1791936000.123456,
            seat_free_at=None,
            current=True,
        ),
        latte.Machine(
            name=None,
            fingerprint="0a1b2c3d4e5f",
            activated_at=1788220800.0,
            last_seen_at=1788300000.5,
            seat_free_at=1792454400.0,
            current=False,
        ),
    ]


@responses.activate
def test_rename_machine_sends_the_name_and_returns_the_stored_one(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/machines/rename",
        json={"machine_name": "Studio Mac"},
        match=[
            responses.matchers.json_params_matcher({**CREDENTIALS, "machine_name": " Studio Mac "})
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    assert sdk.rename_machine(ACTIVATION_ID, TEST_LICENSE_KEY, " Studio Mac ") == "Studio Mac"


@pytest.mark.parametrize(
    ("configured", "sent"),
    [("Studio Mac", "Studio Mac"), (None, socket.gethostname()), ("", None)],
)
@responses.activate
def test_activate_sends_the_machine_name(
    configured: str | None, sent: str | None, tmp_path: Path
) -> None:
    body = {
        "project_key": TEST_APP_ID,
        "license_key": TEST_LICENSE_KEY,
        "machine_id": TEST_DERIVED_MACHINE_ID,
        "sdk": SDK_INFO,
    }
    if sent is not None:
        body["machine_name"] = sent
    responses.add(
        responses.POST,
        f"{BASE_URL}/v1/activate",
        status=401,
        match=[responses.matchers.json_params_matcher(body)],
    )

    with pytest.raises(errors.InvalidProjectKeyError):
        make_sdk(tmp_path / "cache.json", machine_name=configured).activate(TEST_LICENSE_KEY)


# --- background renewal ---

VECTORS = Path(__file__).parent.parent / "testdata" / "vectors"
RENEW_URL = f"{BASE_URL}/v1/renew"


def _vector(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text())


def _response_body(vector: dict) -> dict:
    return {
        "token": vector["token"],
        "activation_id": ACTIVATION_ID,
        "chain": vector["chain"],
    }


def stale_sdk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cached: str = "valid_in_grace_period"
) -> tuple[Sdk, Path, list[float]]:
    """An Sdk whose cache holds the token of vector ``cached`` (by default
    one issued two hours before its clock, past the 60-minute renewal
    marker). It trusts the master keys of both that token and
    ``valid_fresh``, so a renewal answering with the fresh token verifies
    and is told apart from the cached one. The returned one-item list is
    the clock, in unix seconds, set to the vector's ``now``."""
    stale, fresh = _vector(cached), _vector("valid_fresh")
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, stale["token"], CertChain(**stale["chain"]))
    sdk = make_sdk(cache_path)
    sdk._master_pub = [
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["master_public_key_hex"]))
        for v in (stale, fresh)
    ]
    sdk._machine_id = stale["machine_id"]
    clock = [float(calendar.timegm(time.strptime(stale["now"], "%Y-%m-%dT%H:%M:%SZ")))]
    monkeypatch.setattr(latte.http, "time", SimpleNamespace(time=lambda: clock[0]))
    return sdk, cache_path, clock


def _join_renewal(sdk: Sdk) -> None:
    thread = sdk._renew_thread
    assert thread is not None
    thread.join(timeout=5)
    assert not thread.is_alive()


@responses.activate
def test_check_renews_a_token_older_than_an_hour_in_the_background(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    fresh = _vector("valid_fresh")
    # The request names the activation and key the cached token carries.
    stale_credentials = {
        "activation_id": "act_22222222-2222-2222-2222-222222222222",
        "license_key": "AHAK85T628WZ639CMVHF8TNDDX260Z",
        "machine_id": "test-machine-001",
        "sdk": SDK_INFO,
    }
    responses.add(
        responses.POST,
        RENEW_URL,
        json=_response_body(fresh),
        match=[responses.matchers.json_params_matcher(stale_credentials)],
    )

    sdk.check()
    _join_renewal(sdk)

    assert storage.load(cache_path) == (fresh["token"], CertChain(**fresh["chain"]))
    assert sdk._renew_thread is not None and sdk._renew_thread.daemon


@responses.activate
def test_check_does_not_renew_a_token_younger_than_an_hour(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, clock = stale_sdk(tmp_path, monkeypatch)
    clock[0] -= 2 * 3600 - 59 * 60  # token is 59 minutes old

    sdk.check()

    assert sdk._renew_thread is None
    assert len(responses.calls) == 0


@responses.activate
def test_check_renews_a_token_exactly_an_hour_old(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, clock = stale_sdk(tmp_path, monkeypatch)
    responses.add(responses.POST, RENEW_URL, status=500)
    clock[0] -= 3600  # token is exactly 60 minutes old

    sdk.check()
    _join_renewal(sdk)

    assert len(responses.calls) == 1


@responses.activate
def test_check_attempts_a_renewal_at_most_every_five_minutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, clock = stale_sdk(tmp_path, monkeypatch)
    responses.add(responses.POST, RENEW_URL, status=500)

    sdk.check()
    _join_renewal(sdk)
    clock[0] += 299
    sdk.check()
    assert len(responses.calls) == 1

    clock[0] += 1
    sdk.check()
    _join_renewal(sdk)
    assert len(responses.calls) == 2


@responses.activate
def test_check_returns_while_a_renewal_is_blocked_and_starts_no_second_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, clock = stale_sdk(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def blocked(_request: object) -> tuple[int, dict[str, str], str]:
        entered.set()
        assert release.wait(timeout=5)
        return 500, {}, ""

    responses.add_callback(responses.POST, RENEW_URL, callback=blocked)

    first = sdk.check()
    assert entered.wait(timeout=5)
    clock[0] += 10 * 60
    second = sdk.check()  # returns although the first renewal is still blocked

    assert second.key == first.key
    assert len(responses.calls) == 0  # the blocked call has not completed
    release.set()
    _join_renewal(sdk)
    assert len(responses.calls) == 1
    assert storage.load(cache_path) is not None


@pytest.mark.parametrize("status", [401, 403, 404])
@responses.activate
def test_background_renewal_rejected_as_invalid_wipes_the_cache(
    status: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    responses.add(responses.POST, RENEW_URL, status=status)

    sdk.check()
    _join_renewal(sdk)

    assert storage.load(cache_path) is None
    with pytest.raises(errors.NotActivatedError):
        sdk.check()


@responses.activate
def test_background_renewal_rejection_spares_a_cache_that_no_longer_holds_the_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def rejected(_request: object) -> tuple[int, dict[str, str], str]:
        entered.set()
        assert release.wait(timeout=5)
        return 403, {}, ""

    responses.add_callback(responses.POST, RENEW_URL, callback=rejected)

    sdk.check()
    assert entered.wait(timeout=5)
    storage.save(cache_path, "someone-elses-token", garbage_chain())
    release.set()
    _join_renewal(sdk)

    assert storage.load(cache_path) == ("someone-elses-token", garbage_chain())


@responses.activate
def test_background_renewal_does_not_resurrect_a_deactivated_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def renewed(_request: object) -> tuple[int, dict[str, str], str]:
        entered.set()
        assert release.wait(timeout=5)
        return 200, {}, json.dumps(_response_body(_vector("valid_fresh")))

    responses.add_callback(responses.POST, RENEW_URL, callback=renewed)
    responses.add(responses.POST, f"{BASE_URL}/v1/deactivate", json={"released": True})

    sdk.check()
    assert entered.wait(timeout=5)
    sdk.deactivate(ACTIVATION_ID, TEST_LICENSE_KEY)
    release.set()
    _join_renewal(sdk)

    assert storage.load(cache_path) is None


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"status": 500, "json": {"error": "boom"}}, id="server-error"),
        pytest.param({"status": 429}, id="rate-limited"),
        pytest.param({"status": 409}, id="seat-limit"),
        pytest.param({"status": 200, "body": "not json"}, id="undecodable"),
        pytest.param({"status": 200, "json": {"token": ""}}, id="empty-token"),
        pytest.param(
            {"status": 200, "json": {"token": "garbage", "chain": garbage_chain().__dict__}},
            id="token-fails-verification",
        ),
        pytest.param({"body": requests.ConnectionError("down")}, id="network"),
    ],
)
@responses.activate
def test_background_renewal_swallows_every_other_failure_and_keeps_the_cache(
    response: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    before = storage.load(cache_path)
    responses.add(responses.POST, RENEW_URL, **response)

    lic = sdk.check()
    _join_renewal(sdk)

    assert storage.load(cache_path) == before
    assert sdk.check().key == lic.key


@responses.activate
def test_manual_renew_counts_as_an_attempt_for_the_background_schedule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, clock = stale_sdk(tmp_path, monkeypatch)
    responses.add(responses.POST, RENEW_URL, status=500)

    with pytest.raises(errors.ServerError):
        sdk.renew(ACTIVATION_ID, TEST_LICENSE_KEY)
    sdk.check()

    assert sdk._renew_thread is None
    assert len(responses.calls) == 1

    clock[0] += 5 * 60
    sdk.check()
    _join_renewal(sdk)
    assert len(responses.calls) == 2


STALE_ACTIVATION_ID = "act_22222222-2222-2222-2222-222222222222"
STALE_LICENSE_KEY = "AHAK85T628WZ639CMVHF8TNDDX260Z"


def _renew_unreachable(sdk: Sdk) -> None:
    """A manual renewal of the cached activation that never reaches the server."""
    responses.upsert(responses.POST, RENEW_URL, body=requests.ConnectionError("down"))
    with pytest.raises(errors.NetworkError):
        sdk.renew(STALE_ACTIVATION_ID, STALE_LICENSE_KEY)


@responses.activate
def test_a_stale_token_is_not_in_grace_until_a_renewal_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch)
    responses.add(responses.POST, RENEW_URL, status=500)

    assert sdk.check().in_grace_period is False
    _join_renewal(sdk)
    assert sdk.check().in_grace_period is False


@responses.activate
def test_background_renewal_that_cannot_reach_the_server_sets_in_grace_period(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch)
    responses.add(responses.POST, RENEW_URL, body=requests.ConnectionError("down"))

    assert sdk.check().in_grace_period is False  # check does not wait for the renewal
    _join_renewal(sdk)

    assert sdk.check().in_grace_period is True


@responses.activate
def test_manual_renew_that_cannot_reach_the_server_sets_in_grace_period(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch)

    _renew_unreachable(sdk)

    assert sdk.check().in_grace_period is True


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"status": 500, "json": {"error": "boom"}}, id="server-error"),
        pytest.param({"status": 429}, id="rate-limited"),
        pytest.param({"status": 200, "body": "not json"}, id="undecodable"),
        pytest.param(
            {"status": 200, "json": {"token": "garbage", "chain": garbage_chain().__dict__}},
            id="token-fails-verification",
        ),
    ],
)
@responses.activate
def test_a_renewal_that_reaches_the_server_clears_in_grace_period(
    response: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, clock = stale_sdk(tmp_path, monkeypatch)
    _renew_unreachable(sdk)
    responses.upsert(responses.POST, RENEW_URL, **response)
    clock[0] += 5 * 60

    sdk.check()
    _join_renewal(sdk)

    assert sdk.check().in_grace_period is False


@responses.activate
def test_manual_renew_that_reaches_the_server_clears_in_grace_period(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch)
    _renew_unreachable(sdk)
    responses.upsert(responses.POST, RENEW_URL, status=500)

    with pytest.raises(errors.ServerError):
        sdk.renew(STALE_ACTIVATION_ID, STALE_LICENSE_KEY)

    assert sdk.check().in_grace_period is False


@responses.activate
def test_a_successful_renewal_clears_in_grace_period(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, clock = stale_sdk(tmp_path, monkeypatch)
    _renew_unreachable(sdk)
    responses.upsert(responses.POST, RENEW_URL, json=_response_body(_vector("valid_fresh")))
    clock[0] += 5 * 60

    sdk.check()
    _join_renewal(sdk)

    assert sdk.check().in_grace_period is False


@responses.activate
def test_a_rejected_renewal_wipes_the_cache_and_clears_in_grace_period(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, clock = stale_sdk(tmp_path, monkeypatch)
    _renew_unreachable(sdk)
    responses.upsert(responses.POST, RENEW_URL, status=403)
    clock[0] += 5 * 60

    sdk.check()
    _join_renewal(sdk)
    assert storage.load(cache_path) is None

    # The flag does not outlive the wipe: a later activation of a stale
    # token starts from false.
    storage.save(
        cache_path,
        _vector("valid_in_grace_period")["token"],
        CertChain(**_vector("valid_in_grace_period")["chain"]),
    )
    responses.upsert(responses.POST, RENEW_URL, status=500)
    assert sdk.check().in_grace_period is False


@responses.activate
def test_a_failed_attempt_does_not_set_in_grace_period_once_the_cache_moved_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def unreachable(_request: object) -> tuple[int, dict[str, str], str]:
        entered.set()
        assert release.wait(timeout=5)
        raise requests.ConnectionError("down")

    responses.add_callback(responses.POST, RENEW_URL, callback=unreachable)

    sdk.check()
    assert entered.wait(timeout=5)
    storage.save(cache_path, "someone-elses-token", garbage_chain())
    release.set()
    _join_renewal(sdk)

    assert sdk._renewal_failed is False


@responses.activate
def test_deactivate_resets_in_grace_period(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch)
    _renew_unreachable(sdk)
    responses.add(responses.POST, f"{BASE_URL}/v1/deactivate", json={"released": True})

    sdk.deactivate(STALE_ACTIVATION_ID, STALE_LICENSE_KEY)

    assert sdk._renewal_failed is False


@responses.activate
def test_activate_resets_in_grace_period(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch)
    _renew_unreachable(sdk)
    storage.clear(cache_path)
    fresh = _vector("valid_fresh")
    responses.add(responses.POST, f"{BASE_URL}/v1/activate", json=_response_body(fresh))

    sdk.activate(TEST_LICENSE_KEY)

    assert sdk._renewal_failed is False
    assert sdk.check().in_grace_period is False


def test_check_without_a_cache_starts_no_renewal(tmp_path: Path) -> None:
    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    assert sdk._renew_thread is None


# --- renewal of a token the offline checks reject ---


@responses.activate
def test_check_renews_a_signed_token_past_its_grace_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch, "expired_past_grace_deadline")
    fresh = _vector("valid_fresh")
    responses.add(responses.POST, RENEW_URL, json=_response_body(fresh))

    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)

    assert len(responses.calls) == 1
    assert json.loads(responses.calls[0].request.body) == {
        "activation_id": "act_22222222-2222-2222-2222-222222222222",
        "license_key": "AHAK85T628WZ639CMVHF8TNDDX260Z",
        "machine_id": "test-machine-001",
        "sdk": SDK_INFO,
    }
    assert storage.load(cache_path) == (fresh["token"], CertChain(**fresh["chain"]))
    assert not sdk.check().in_grace_period
    assert len(responses.calls) == 1


@responses.activate
def test_check_renews_a_hard_expired_signed_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch, "expired_hard_expiry")
    responses.add(responses.POST, RENEW_URL, json=_response_body(_vector("valid_fresh")))

    with pytest.raises(errors.LicenseExpiredError):
        sdk.check()
    _join_renewal(sdk)

    assert sdk.check().key


@responses.activate
def test_check_renews_a_token_whose_daily_cert_has_expired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch, "offline_after_daily_cert_expiry")
    fresh = _vector("valid_fresh")
    responses.add(responses.POST, RENEW_URL, json=_response_body(fresh))

    sdk.check()
    _join_renewal(sdk)

    assert len(responses.calls) == 1
    assert storage.load(cache_path) == (fresh["token"], CertChain(**fresh["chain"]))


@pytest.mark.parametrize("cached", ["tampered_payload", "invalid_signature", "machine_id_mismatch"])
@responses.activate
def test_check_does_not_renew_an_unsigned_or_foreign_token(
    cached: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, clock = stale_sdk(tmp_path, monkeypatch, cached)
    clock[0] += 30 * 24 * 3600  # long past any grace deadline
    before = storage.load(cache_path)

    with pytest.raises(errors.NotActivatedError):
        sdk.check()

    assert sdk._renew_thread is None
    assert len(responses.calls) == 0
    assert storage.load(cache_path) == before


@pytest.mark.parametrize("status", [401, 403, 404])
@responses.activate
def test_renewal_of_a_lapsed_token_rejected_as_invalid_wipes_the_cache(
    status: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, _ = stale_sdk(tmp_path, monkeypatch, "expired_past_grace_deadline")
    responses.add(responses.POST, RENEW_URL, status=status)

    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)

    assert storage.load(cache_path) is None


@responses.activate
def test_renewal_of_a_lapsed_token_that_cannot_reach_the_server_keeps_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, clock = stale_sdk(tmp_path, monkeypatch, "expired_past_grace_deadline")
    before = storage.load(cache_path)
    responses.add(responses.POST, RENEW_URL, body=ConnectionError("down"))

    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)
    assert storage.load(cache_path) == before

    clock[0] += 4 * 60  # inside the five-minute floor
    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    assert len(responses.calls) == 1

    clock[0] += 60
    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)
    assert len(responses.calls) == 2


@responses.activate
def test_renewal_rejection_wipes_a_cache_whose_project_cert_has_expired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, cache_path, clock = stale_sdk(tmp_path, monkeypatch, "expired_past_grace_deadline")
    clock[0] = 1799064000.0 + 86400  # a day past the cached chain's project cert
    responses.add(responses.POST, RENEW_URL, status=403)

    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)

    assert storage.load(cache_path) is None


@pytest.mark.parametrize(
    ("response", "failed"),
    [
        pytest.param({"body": requests.ConnectionError("down")}, True, id="network"),
        pytest.param({"status": 500}, False, id="server-error"),
        pytest.param({"status": 429}, False, id="rate-limited"),
    ],
)
@responses.activate
def test_renewal_of_a_lapsed_token_sets_the_flag_only_when_the_server_is_unreachable(
    response: dict, failed: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch, "expired_past_grace_deadline")
    sdk._renewal_failed = not failed
    responses.add(responses.POST, RENEW_URL, **response)

    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)

    assert sdk._renewal_failed is failed


@responses.activate
def test_a_successful_renewal_of_a_lapsed_token_clears_the_flag_and_the_license_is_not_in_grace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdk, _, _ = stale_sdk(tmp_path, monkeypatch, "expired_past_grace_deadline")
    sdk._renewal_failed = True
    responses.add(responses.POST, RENEW_URL, json=_response_body(_vector("valid_fresh")))

    with pytest.raises(errors.NotActivatedError):
        sdk.check()
    _join_renewal(sdk)

    assert sdk._renewal_failed is False
    assert not sdk.check().in_grace_period
