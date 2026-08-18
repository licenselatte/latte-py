"""``Sdk``: activates and renews licenses over the network, with an
optional on-disk cache so repeat launches don't need a network call.

Two independent things this module depends on, both bundled by default:

- ``requests`` for the network calls (``activate``/``renew``).
- ``platformdirs`` for locating the on-disk cache (``Config.cache``,
  ``check``, and the fast path inside ``activate``/``renew``).

Neither is behind a feature flag the way they would be in a compiled
language: set ``Config.cache = False`` to skip the cache entirely (a
sandboxed environment with no writable filesystem, for instance); there's
no equivalent toggle for the network calls, since without them ``Sdk``
has nothing left to do (use ``verify.verify_activation_at``/
``validate.validate_at`` directly if you want to supply your own HTTP
client instead).

``activate``/``renew`` always go over the network on a cache miss; there's
no background renewal thread here: call ``renew`` yourself on whatever
schedule fits your application.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import requests

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import errors, storage, validate, verify
from .appid import parse_app_id
from .domain import CertChain
from .key import normalize_key, sanitize_key
from .license import PublicLicense, check_license_at

# The Ed25519 public key used to verify every certificate chain. This is a
# public key, not a secret: it's meant to be embedded in every SDK.
_MASTER_PUBLIC_KEY_HEX = "6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb"

_DEFAULT_TIMEOUT = 30.0

_INVALIDATING_ERRORS = (
    errors.LicenseNotFoundError,
    errors.LicenseExpiredError,
    errors.InvalidProjectKeyError,
)


@dataclass
class Config:
    """Configuration for ``Sdk``."""

    app_id: str
    """``pk_{env}_{32-char key}``, shown in the LicenseLatte dashboard."""

    timeout: float = _DEFAULT_TIMEOUT
    """Request timeout (seconds) for ``activate``/``renew``."""

    base_url: str | None = None
    """Override the API base URL that ``app_id``'s environment would
    otherwise select. Useful for routing through a corporate
    proxy/self-hosted relay, or for pointing tests at a mock server.
    ``None`` uses the environment default.
    """

    cache: bool = True
    """Whether to use an on-disk cache at all. Set to ``False`` for a
    sandboxed/read-only-filesystem environment; ``activate``/``renew``
    then always go over the network, and ``check`` always raises
    ``NotActivatedError``.
    """

    cache_path: Path | None = None
    """Override where the on-disk token cache lives. ``None`` resolves a
    per-project default location. Ignored if ``cache`` is ``False``.
    """


class Sdk:
    """Activates and renews licenses over the network, with an optional
    local cache so a valid activation survives across process restarts
    without a network round trip.
    """

    def __init__(self, config: Config) -> None:
        parsed = parse_app_id(config.app_id)  # raises an AppIdError subclass

        self._base_url = config.base_url or parsed.base_url
        self._app_id = config.app_id
        self._app_key = parsed.key
        self._timeout = config.timeout
        self._master_pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(_MASTER_PUBLIC_KEY_HEX)
        )
        self._session = requests.Session()
        self._cache_path: Path | None = None
        if config.cache:
            self._cache_path = config.cache_path or storage.default_path(parsed.key)

    def activate(self, license_key: str, machine_id: str) -> PublicLicense:
        """Activates ``license_key`` for ``machine_id``.

        The key is normalized and given a minimal sanity check (non-empty,
        not implausibly long) before ever reaching the network — a
        license key may be native or a legacy-system alias (see the
        legacy-key-migration feature in license-latte-api,
        internal/usecase/api/activate_license.go), and only the server
        knows which, so anything beyond that minimal check is deferred to
        it.

        With caching enabled, a cached activation for this exact key is
        tried first; if it's still valid, it's returned without a network
        call. A cache hit matches either the cached license's native key
        (``sub`` claim) against the sanitized input, or — for a license
        resolved via a legacy-key alias, where ``sub`` is the newly
        minted native key rather than the string the caller keeps
        passing — its ``alias`` claim against the normalized input. Any
        other outcome (no cache, a cache for a different key, or a cached
        token that fails verification/validation) falls through to a
        network call, and a successful result is written back to the
        cache. A server response that fails local verification/validation
        raises ``ServerError``, not one of the sentinel exceptions (those
        are reserved for the server's HTTP status code itself).
        """
        sanitized = sanitize_key(license_key)
        normalized = normalize_key(license_key)
        self._validate_license_key(normalized)

        cached = self._cached_license(machine_id)
        if cached is not None:
            public, alias = cached
            if public.key == sanitized or (alias != "" and alias == normalized):
                return public

        token, chain = self._post_and_handle_invalidation(
            "/v1/activate",
            {
                "project_key": self._app_id,
                "license_key": normalized,
                "machine_id": machine_id,
            },
        )
        lic = self._verify_and_validate(token, chain, machine_id)
        self._save_to_cache(token, chain)
        return lic

    def renew(self, activation_id: str, license_key: str, machine_id: str) -> PublicLicense:
        """Renews an existing activation.

        Unlike ``activate``, this does not re-check the license-key format
        against the project key: it trusts the caller already holds a
        valid ``activation_id`` (from a prior ``activate`` call's
        ``PublicLicense.activation_id``). Also unlike ``activate``'s
        request, the wire request here carries no project-key field. On
        success, and with caching enabled, the renewed token replaces
        whatever was previously cached.
        """
        token, chain = self._post_and_handle_invalidation(
            "/v1/renew",
            {
                "activation_id": activation_id,
                "license_key": license_key,
                "machine_id": machine_id,
            },
        )
        lic = self._verify_and_validate(token, chain, machine_id)
        self._save_to_cache(token, chain)
        return lic

    def check(self, machine_id: str) -> PublicLicense:
        """Reads the cached activation for ``machine_id`` without making a
        network call.

        Raises ``LicenseExpiredError`` if there's a cached token but it's
        past its hard expiry, and ``NotActivatedError`` for every other
        reason there's no currently-usable cached license: caching is
        disabled, nothing is cached, the cache fails signature
        verification (corrupt, tampered, or simply not something this key
        can verify), or it's valid but rejected for a different reason
        (out of its grace window, too old, or for a different machine ID):
        those don't get their own exception because the caller's
        correct response to all of them is the same: activate again.
        """
        if self._cache_path is None:
            raise errors.NotActivatedError("not activated on this machine")
        cached = storage.load(self._cache_path)
        if cached is None:
            raise errors.NotActivatedError("not activated on this machine")

        token, chain = cached
        try:
            return check_license_at(self._master_pub, token, chain, machine_id, time.time())
        except errors.HardExpiredError as e:
            raise errors.LicenseExpiredError("license expired") from e
        except (errors.VerifyError, errors.ValidateError) as e:
            raise errors.NotActivatedError("not activated on this machine") from e

    def _validate_license_key(self, normalized: str) -> None:
        """A minimal local sanity check, not a format check: a license key
        may be native or a legacy-system alias (see the legacy-key-migration
        feature in license-latte-api,
        internal/usecase/api/activate_license.go), and only the server
        knows which. This exists
        only to reject obviously-not-a-key input (empty, or implausibly
        long) without a network round trip.
        """
        if len(normalized) == 0 or len(normalized) > 256:
            raise errors.InvalidKeyError("invalid license key")

    def _cached_license(self, machine_id: str) -> tuple[PublicLicense, str] | None:
        """Verifies+validates the cached token, if any, returning both its
        public-facing shape and its (internal-only) alias claim so the
        fast path in ``activate`` can match a legacy-key alias too.
        """
        if self._cache_path is None:
            return None
        cached = storage.load(self._cache_path)
        if cached is None:
            return None
        token, chain = cached
        try:
            now = time.time()
            lic = verify.verify_activation_at(self._master_pub, token, chain, now)
            validate.validate_at(lic, machine_id, now)
        except (errors.VerifyError, errors.ValidateError):
            return None
        public = PublicLicense(
            key=lic.key,
            activation_id=lic.activation_id,
            project_id=lic.project_id,
            issued_at=lic.issued_at,
            expires_at=lic.expires_at,
            grace_period_secs=lic.grace_period_secs,
            in_grace_period=validate.in_grace_period(lic, now),
            license_type=lic.license_type,
            metadata=lic.metadata,
        )
        return public, lic.alias

    def _save_to_cache(self, token: str, chain: CertChain) -> None:
        if self._cache_path is not None:
            # Best-effort: a local write failure shouldn't turn a
            # successful network activation into an error.
            try:
                storage.save(self._cache_path, token, chain)
            except OSError:
                pass

    def _clear_cache(self) -> None:
        if self._cache_path is not None:
            try:
                storage.clear(self._cache_path)
            except OSError:
                pass

    def _verify_and_validate(
        self, token: str, chain: CertChain, machine_id: str
    ) -> PublicLicense:
        try:
            return check_license_at(self._master_pub, token, chain, machine_id, time.time())
        except (errors.VerifyError, errors.ValidateError) as e:
            raise errors.ServerError(f"server returned invalid token: {e}") from e

    def _post_and_handle_invalidation(
        self, path: str, body: dict[str, str]
    ) -> tuple[str, CertChain]:
        """Calls ``_post``, and on a response that unambiguously means
        "this activation no longer exists" (not found / expired / wrong
        project key), drops any cached token for this project too:
        otherwise a later ``check``/``activate`` fast path would keep
        treating a server-revoked license as still active until it
        independently expires.
        """
        try:
            return self._post(path, body)
        except _INVALIDATING_ERRORS:
            self._clear_cache()
            raise

    def _post(self, path: str, body: dict[str, str]) -> tuple[str, CertChain]:
        """Shared POST helper for ``activate``/``renew``."""
        try:
            resp = self._session.post(
                self._base_url + path, json=body, timeout=self._timeout
            )
        except requests.RequestException as e:
            raise errors.NetworkError(str(e)) from e

        if not (200 <= resp.status_code < 300):
            try:
                msg = resp.json().get("error", "") or ""
            except ValueError:
                msg = ""
            if resp.status_code == 404:
                raise errors.LicenseNotFoundError("license not found")
            if resp.status_code == 403:
                raise errors.LicenseExpiredError("license inactive or expired")
            if resp.status_code == 409:
                raise errors.SeatLimitError("activation seat limit reached")
            if resp.status_code == 401:
                raise errors.InvalidProjectKeyError("invalid project key")
            raise errors.ServerError(msg or f"HTTP {resp.status_code}")

        try:
            data = resp.json()
        except ValueError as e:
            raise errors.ServerError(f"decode response: {e}") from e

        token = data.get("token") or ""
        chain_data = data.get("chain") or {}
        if not token:
            raise errors.ServerError("server returned empty token")
        if not chain_data.get("daily") or not chain_data.get("project") or not chain_data.get(
            "submaster"
        ):
            raise errors.ServerError("server returned empty chain")

        return token, CertChain(
            submaster=chain_data["submaster"],
            project=chain_data["project"],
            daily=chain_data["daily"],
        )
