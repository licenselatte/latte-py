"""Tests for `Sdk.activate`/`Sdk.renew`/`Sdk.check` against a mocked
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

from pathlib import Path

import pytest
import responses

from latte import errors, storage
from latte.domain import CertChain
from latte.http import Config, Sdk

# A valid AppID (pk_test_{28-char data}{4-char checksum}) and a matching
# license key ({6-char short_id}{22 random}{2-char checksum}), computed
# against the checksum algorithm in latte/key.py.
TEST_APP_ID = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS"
TEST_LICENSE_KEY = "AHAK85BCDEFGHJKMNPQRSTVWXYZ00Z"
TEST_MACHINE_ID = "test-machine-id"
BASE_URL = "https://mock.invalid"


def make_sdk(cache_path: Path) -> Sdk:
    return Sdk(Config(app_id=TEST_APP_ID, base_url=BASE_URL, cache_path=cache_path))


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
                    "machine_id": TEST_MACHINE_ID,
                }
            )
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError):
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


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
                    "machine_id": TEST_MACHINE_ID,
                }
            )
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError):
        sdk.renew(activation_id, TEST_LICENSE_KEY, TEST_MACHINE_ID)


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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


@responses.activate
def test_transport_failure_is_a_network_error(tmp_path: Path) -> None:
    # No responses.add() registered for this URL, so `responses` raises a
    # ConnectionError for it, simulating a request that never got a
    # response (DNS/TCP/timeout).
    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.NetworkError):
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


def test_empty_license_key_never_reaches_the_network(tmp_path: Path) -> None:
    # No @responses.activate at all: if activate() incorrectly made a
    # network call here, `requests` would try a real DNS lookup against
    # "mock.invalid" and fail loudly, so this test would fail either way a
    # bug could manifest.
    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.InvalidKeyError):
        sdk.activate("", TEST_MACHINE_ID)


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
                    "machine_id": TEST_MACHINE_ID,
                }
            )
        ],
    )

    sdk = make_sdk(tmp_path / "cache.json")
    with pytest.raises(errors.ServerError):
        sdk.activate(legacy_key, TEST_MACHINE_ID)


# --- cache ---


def test_check_reports_not_activated_when_nothing_is_cached(tmp_path: Path) -> None:
    sdk = Sdk(Config(app_id=TEST_APP_ID, cache_path=tmp_path / "cache.json"))
    with pytest.raises(errors.NotActivatedError):
        sdk.check(TEST_MACHINE_ID)


def test_check_reports_not_activated_when_caching_is_disabled(tmp_path: Path) -> None:
    sdk = Sdk(Config(app_id=TEST_APP_ID, cache=False, cache_path=tmp_path / "cache.json"))
    with pytest.raises(errors.NotActivatedError):
        sdk.check(TEST_MACHINE_ID)


def test_check_reports_not_activated_for_a_cache_that_fails_verification(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())

    sdk = Sdk(Config(app_id=TEST_APP_ID, cache_path=cache_path))
    with pytest.raises(errors.NotActivatedError):
        sdk.check(TEST_MACHINE_ID)


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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)


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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)

    assert storage.load(cache_path) is None


@responses.activate
def test_activate_clears_an_existing_cache_entry_on_license_not_found(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(responses.POST, f"{BASE_URL}/v1/activate", status=404)

    sdk = make_sdk(cache_path)
    with pytest.raises(errors.LicenseNotFoundError):
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)

    assert storage.load(cache_path) is None


@responses.activate
def test_renew_clears_an_existing_cache_entry_on_license_expired(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    storage.save(cache_path, "not-a-real-jwt", garbage_chain())
    responses.add(responses.POST, f"{BASE_URL}/v1/renew", status=403)

    sdk = make_sdk(cache_path)
    activation_id = "11111111-1111-1111-1111-111111111111"
    with pytest.raises(errors.LicenseExpiredError):
        sdk.renew(activation_id, TEST_LICENSE_KEY, TEST_MACHINE_ID)

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
        sdk.activate(TEST_LICENSE_KEY, TEST_MACHINE_ID)

    # A 500 doesn't mean the activation is gone, just that something else
    # went wrong: an existing cache entry (unverifiable or not) shouldn't
    # be touched over it.
    assert cache_path.exists()
