"""``Sdk``: activates and renews licenses over the network, with an
optional on-disk cache so repeat launches don't need a network call.

Two independent things this module depends on, both bundled by default:

- ``requests`` for the network calls (``activate``/``renew`` and the
  machine calls ``deactivate``/``machines``/``rename_machine``).
- ``platformdirs`` for locating the on-disk cache (``Config.cache``,
  ``check``, and the fast path inside ``activate``/``renew``).

Neither is behind a feature flag the way they would be in a compiled
language: set ``Config.cache = False`` to skip the cache entirely (a
sandboxed environment with no writable filesystem, for instance); there's
no equivalent toggle for the network calls, since without them ``Sdk``
has nothing left to do (use ``verify.verify_activation_at``/
``validate.validate_at`` directly if you want to supply your own HTTP
client instead).

``activate``/``renew`` always go over the network on a cache miss. ``check``
renews in the background: once the cached token is an hour old it starts a
daemon thread that calls ``/v1/renew``, at most once every five minutes and
never while another renewal is running, without ever making ``check`` wait.
``renew`` stays available for a schedule of your own.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from . import errors, machineid, storage, validate, verify
from .appid import parse_app_id
from .domain import CertChain, License
from .key import normalize_key, sanitize_key
from .license import PublicLicense, _to_public_license, check_license_at

_DEFAULT_TIMEOUT = 30.0

# A background renewal starts once the cached token is this old, and no more
# often than every _MIN_RENEW_INTERVAL_SECS.
_RENEW_AFTER_SECS = validate._MAX_RENEWAL_TIME_SECS
_MIN_RENEW_INTERVAL_SECS = 5 * 60

# What check() rejects a signed token for when only time has passed.
_LAPSED_ERRORS = (
    errors.ExpiredError,
    errors.HardExpiredError,
    errors.GraceExpiredError,
    errors.LicenseTooOldError,
)

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
    """Request timeout (seconds) for every network call."""

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

    machine_id: str | None = None
    """A raw machine ID to use instead of the platform's. ``None`` or empty
    reads the platform machine ID. Either way the SDK sends only its
    HMAC-SHA256 under ``app_id`` (see ``latte.machineid``), never the raw
    value.

    Supply one when the platform ID does not identify one seat: containers
    that share an image's ``/etc/machine-id`` or have none, cloned VMs, a
    seat per user rather than per machine, and tests. Changing it on an
    activated install counts as a new machine.
    """

    machine_name: str | None = None
    """The name this machine is given when it activates, shown to the
    customer by ``machines`` and the customer portal and to you in the
    dashboard. ``None`` sends the OS hostname; ``""`` sends no name. A name
    the customer sets later with ``rename_machine`` is kept on
    re-activation.
    """


@dataclass(frozen=True)
class DeactivateResult:
    """What ``Sdk.deactivate`` reports."""

    released: bool
    """``False`` when the machine was already released, on an earlier call
    or by the seller. Both outcomes are success."""

    seat_free_at: float | None
    """When (unix seconds) the freed seat can be used by another machine,
    set when the seller's policy holds it until this machine's last token
    has expired. ``None`` means the seat is free now."""


@dataclass(frozen=True)
class Machine:
    """One machine holding a seat on a licence, as ``Sdk.machines`` lists
    it. It identifies a machine for a person to recognise and is never a
    handle for acting on one. Times are unix seconds."""

    name: str | None
    """The machine's name, ``None`` when it has none."""
    fingerprint: str
    """The first 12 characters of the machine ID hash."""
    activated_at: float
    last_seen_at: float
    """The machine's last activation or renewal."""
    seat_free_at: float | None
    """Set on a released machine whose seat the seller's policy still
    holds, and is when that seat frees."""
    current: bool
    """Marks the machine the SDK is running on."""


class Sdk:
    """Activates and renews licenses over the network, with an optional
    local cache so a valid activation survives across process restarts
    without a network round trip.
    """

    def __init__(self, config: Config) -> None:
        parsed = parse_app_id(config.app_id)  # raises an AppIdError subclass
        raw = config.machine_id or machineid.read_platform_id()  # raises MachineIdError
        self._machine_id = machineid.protected_id(raw, config.app_id)

        self._base_url = config.base_url or parsed.base_url
        self._app_id = config.app_id
        self._app_key = parsed.key
        self._timeout = config.timeout
        self._master_pub = verify.MASTER_PUBLIC_KEYS
        # Imported here because the package imports this module before it
        # defines __version__.
        from . import __version__

        self._sdk_info = {"language": "python", "version": __version__}
        self._session = requests.Session()
        self._machine_name = config.machine_name
        if self._machine_name is None:
            # The name is a courtesy, so a hostname the OS will not give is no name.
            try:
                self._machine_name = socket.gethostname()
            except OSError:
                self._machine_name = ""
        # Guards the cache file, so a background renewal's check-then-write
        # is atomic against deactivate and manual renew.
        self._cache_lock = threading.RLock()
        # Guards the next two fields; never held across a network call.
        self._renew_lock = threading.Lock()
        self._renew_in_flight = False
        self._last_renew_attempt = 0.0
        self._renew_thread: threading.Thread | None = None
        self._cache_path: Path | None = None
        if config.cache:
            self._cache_path = config.cache_path or storage.default_path(parsed.key)

    @property
    def machine_id(self) -> str:
        """The derived machine ID this SDK sends and validates against.
        Pass it to ``check_license``/``check_license_at`` when checking a
        token yourself."""
        return self._machine_id

    def activate(self, license_key: str) -> PublicLicense:
        """Activates ``license_key`` on this machine.

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

        cached = self._cached_license()
        if cached is not None:
            public, alias = cached
            if public.key == sanitized or (alias != "" and alias == normalized):
                return public

        body: dict[str, object] = {
            "project_key": self._app_id,
            "license_key": normalized,
            "machine_id": self._machine_id,
            "sdk": self._sdk_info,
        }
        if self._machine_name:
            body["machine_name"] = self._machine_name
        token, chain = self._post_and_handle_invalidation("/v1/activate", body)
        lic = self._verify_and_validate(token, chain)
        self._save_to_cache(token, chain)
        return lic

    def renew(self, activation_id: str, license_key: str) -> PublicLicense:
        """Renews an existing activation.

        Unlike ``activate``, this does not re-check the license-key format
        against the project key: it trusts the caller already holds a
        valid ``activation_id`` (from a prior ``activate`` call's
        ``PublicLicense.activation_id``). Also unlike ``activate``'s
        request, the wire request here carries no project-key field. On
        success, and with caching enabled, the renewed token replaces
        whatever was previously cached. It counts as a renewal attempt for
        the background schedule of ``check``.
        """
        with self._renew_lock:
            self._last_renew_attempt = time.time()
        token, chain = self._post_and_handle_invalidation(
            "/v1/renew", self._credentials(activation_id, license_key)
        )
        lic = self._verify_and_validate(token, chain)
        self._save_to_cache(token, chain)
        return lic

    def deactivate(self, activation_id: str, license_key: str) -> DeactivateResult:
        """Releases this machine's seat so the licence can be activated on
        another machine. Takes the same credentials as ``renew``.

        It needs the network: the server releases the seat first, and only
        once it has answered does the SDK delete the cached token (with
        caching enabled), after which ``check`` raises
        ``NotActivatedError`` until the next ``activate``. When the call
        fails, the cache is kept and the call can be retried; a machine
        that is lost or dead is released from the seller's customer portal
        instead.

        A release that already happened, on this call or an earlier one, is
        success. When the seller's policy refuses the release, this raises
        ``DeactivationBlockedError``.
        """
        resp = self._send("/v1/deactivate", self._credentials(activation_id, license_key))
        if resp.status_code == 409:
            # The seller's deactivation policy, never a seat limit.
            body = _error_body(resp)
            try:
                available_at = _parse_time(body["available_at"])
            except (KeyError, TypeError, ValueError):
                available_at = None
            raise errors.DeactivationBlockedError(
                body.get("error") or "deactivation blocked",
                reason=body.get("reason") or "",
                available_at=available_at,
            )
        data = _decode(resp)
        self._clear_cache()
        try:
            seat_free_at = data.get("seat_free_at")
            return DeactivateResult(
                released=bool(data.get("released")),
                seat_free_at=_parse_time(seat_free_at) if seat_free_at else None,
            )
        except (AttributeError, TypeError, ValueError) as e:
            raise errors.ServerError(f"decode response: {e}") from e

    def machines(self, activation_id: str, license_key: str) -> list[Machine]:
        """Lists the machines holding a seat on this activation's licence.
        Takes the same credentials as ``renew`` and needs the network."""
        data = _decode(self._send("/v1/machines", self._credentials(activation_id, license_key)))
        try:
            return [
                Machine(
                    name=m.get("machine_name") or None,
                    fingerprint=m["machine_fingerprint"],
                    activated_at=_parse_time(m["activated_at"]),
                    last_seen_at=_parse_time(m["last_seen_at"]),
                    seat_free_at=_parse_time(m["seat_free_at"]) if m.get("seat_free_at") else None,
                    current=bool(m.get("current")),
                )
                for m in data["machines"]
            ]
        except (AttributeError, KeyError, TypeError, ValueError) as e:
            raise errors.ServerError(f"decode response: {e}") from e

    def rename_machine(self, activation_id: str, license_key: str, name: str) -> str:
        """Names this machine and returns the name as stored, trimmed.
        Takes the same credentials as ``renew`` and needs the network. The
        server refuses a name that is empty, longer than 64 characters or
        holds control characters (``ServerError``)."""
        body = self._credentials(activation_id, license_key)
        body["machine_name"] = name
        data = _decode(self._send("/v1/machines/rename", body))
        try:
            return str(data["machine_name"])
        except (KeyError, TypeError) as e:
            raise errors.ServerError(f"decode response: {e}") from e

    def check(self) -> PublicLicense:
        """Reads the cached activation for this machine without making a
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

        When the cached token is an hour old or more, ``check`` also starts a
        renewal on a daemon thread and returns without waiting for it: at
        most one at a time and one attempt per five minutes. A renewal the
        server rejects as invalid or inactive clears the cache, so the next
        ``check`` raises ``NotActivatedError``; a success replaces the
        cached token; every other failure is ignored and the cached token
        stays valid until its grace deadline.
        """
        if self._cache_path is None:
            raise errors.NotActivatedError("not activated on this machine")
        cached = storage.load(self._cache_path)
        if cached is None:
            raise errors.NotActivatedError("not activated on this machine")

        token, chain = cached
        now = time.time()
        try:
            lic = check_license_at(self._master_pub, token, chain, self._machine_id, now)
        except _LAPSED_ERRORS as e:
            self._renew_lapsed(token, chain, now)
            if isinstance(e, errors.HardExpiredError):
                raise errors.LicenseExpiredError("license expired") from e
            raise errors.NotActivatedError("not activated on this machine") from e
        except (errors.VerifyError, errors.ValidateError) as e:
            raise errors.NotActivatedError("not activated on this machine") from e
        self._renew_in_background(lic, now)
        return lic

    def _renew_lapsed(self, token: str, chain: CertChain, now: float) -> None:
        """Starts a renewal for a token ``check`` rejected only because time
        has passed, so a computer that was off past the grace window recovers
        by itself. The signature chain and the machine ID must still hold,
        and the activation and key come from the signed token."""
        try:
            lic = verify.verify_activation_at(
                self._master_pub, token, chain, now, ignore_expiry=True
            )
        except errors.VerifyError:
            return
        if lic.machine_id == self._machine_id:
            self._renew_in_background(lic, now)

    def _renew_in_background(self, lic: PublicLicense | License, now: float) -> None:
        """Starts a renewal thread for ``lic`` if it is due and none is
        running."""
        if now - lic.issued_at < _RENEW_AFTER_SECS:
            return
        with self._renew_lock:
            if self._renew_in_flight or now - self._last_renew_attempt < _MIN_RENEW_INTERVAL_SECS:
                return
            self._renew_in_flight = True
            self._last_renew_attempt = now
        self._renew_thread = threading.Thread(
            target=self._background_renew, args=(lic.activation_id, lic.key), daemon=True
        )
        self._renew_thread.start()

    def _background_renew(self, activation_id: str, license_key: str) -> None:
        """Renews ``activation_id`` and touches the cache only while it
        still holds that activation. Nothing escapes: the cached token stays
        valid until its grace deadline."""
        try:
            try:
                token, chain = self._post(
                    "/v1/renew", self._credentials(activation_id, license_key)
                )
                self._verify_and_validate(token, chain)
            except _INVALIDATING_ERRORS:
                with self._cache_lock:
                    if self._cache_holds(activation_id):
                        self._clear_cache()
                return
            with self._cache_lock:
                if self._cache_holds(activation_id):
                    self._save_to_cache(token, chain)
        except Exception:  # noqa: BLE001, S110 - nothing may escape the thread
            pass
        finally:
            with self._renew_lock:
                self._renew_in_flight = False

    def _cache_holds(self, activation_id: str) -> bool:
        """Whether the cache holds a signed token for ``activation_id``, even
        one whose certs have expired."""
        if self._cache_path is None:
            return False
        cached = storage.load(self._cache_path)
        if cached is None:
            return False
        try:
            lic = verify.verify_activation_at(
                self._master_pub, *cached, time.time(), ignore_expiry=True
            )
        except errors.VerifyError:
            return False
        return lic.activation_id == activation_id

    def _credentials(self, activation_id: str, license_key: str) -> dict[str, object]:
        """The request body ``renew`` and the machine calls share."""
        return {
            "activation_id": activation_id,
            "license_key": license_key,
            "machine_id": self._machine_id,
            "sdk": self._sdk_info,
        }

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

    def _cached_license(self) -> tuple[PublicLicense, str] | None:
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
            validate.validate_at(lic, self._machine_id, now)
        except (errors.VerifyError, errors.ValidateError):
            return None
        public = _to_public_license(lic, validate.in_grace_period(lic, now))
        return public, lic.alias

    def _save_to_cache(self, token: str, chain: CertChain) -> None:
        if self._cache_path is not None:
            # Best-effort: a local write failure shouldn't turn a
            # successful network activation into an error.
            try:
                with self._cache_lock:
                    storage.save(self._cache_path, token, chain)
            except OSError:
                pass

    def _clear_cache(self) -> None:
        if self._cache_path is not None:
            try:
                with self._cache_lock:
                    storage.clear(self._cache_path)
            except OSError:
                pass

    def _verify_and_validate(self, token: str, chain: CertChain) -> PublicLicense:
        try:
            return check_license_at(self._master_pub, token, chain, self._machine_id, time.time())
        except (errors.VerifyError, errors.ValidateError) as e:
            raise errors.ServerError(f"server returned invalid token: {e}") from e

    def _post_and_handle_invalidation(
        self, path: str, body: dict[str, object]
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

    def _post(self, path: str, body: dict[str, object]) -> tuple[str, CertChain]:
        """Shared POST helper for ``activate``/``renew``."""
        data = _decode(self._send(path, body))

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

    def _send(self, path: str, body: dict[str, object]) -> requests.Response:
        """POSTs ``body`` as JSON to ``path``, raising ``NetworkError`` when
        no response arrives."""
        try:
            return self._session.post(self._base_url + path, json=body, timeout=self._timeout)
        except requests.RequestException as e:
            raise errors.NetworkError(str(e)) from e


def _error_body(resp: requests.Response) -> dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _decode(resp: requests.Response) -> Any:
    """Returns the decoded JSON of a 2xx response, or raises the error its
    status stands for."""
    if not (200 <= resp.status_code < 300):
        msg = _error_body(resp).get("error", "") or ""
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
        return resp.json()
    except ValueError as e:
        raise errors.ServerError(f"decode response: {e}") from e


def _parse_time(value: str) -> float:
    """Parses an RFC 3339 timestamp into unix seconds. Before Python 3.11,
    ``fromisoformat`` reads neither ``Z`` nor a fraction of other than 3 or
    6 digits, so both are rewritten first."""
    value = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), value)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
