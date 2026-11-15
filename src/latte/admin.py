"""Server-side client for the LicenseLatte admin REST API: issue, inspect,
update, suspend, revoke and release licenses from your own backend.

An API key is a secret. Import this module only in code you run yourself and
never in an application you ship to end users. ``latte.Sdk`` is the
client-side API and needs no secret.

Objects mirror the API's JSON. Timestamps stay RFC 3339 strings, and the
whole decoded object is kept in ``raw`` so fields this version does not model
remain readable.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar
from urllib.parse import quote

import requests

from . import errors

DEFAULT_BASE_URL = "https://api.licenselatte.com/v1"
_DEFAULT_TIMEOUT = 30.0


class AdminError(errors.LatteError):
    """A non-2xx answer from the API. Branch on ``status_code``; ``message``
    is written for a human reading a log. ``code`` is a machine-readable
    refusal code when the API sends one, such as
    ``"plan_license_limit_reached"`` on a 409 from ``issue_license``."""

    def __init__(self, status_code: int, message: str, code: str | None = None) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.code = code


class _Unset:
    def __repr__(self) -> str:
        return "UNSET"


#: Marks an ``update_license`` field to leave alone (``None`` is a real value
#: for ``expires_at``: it clears the expiry).
UNSET: Any = _Unset()

_T = TypeVar("_T")


def _build(cls: type[_T], d: Mapping[str, Any]) -> _T:
    ctor: Any = cls
    names = {f.name for f in dataclasses.fields(ctor) if f.name != "raw"}
    return ctor(**{k: v for k, v in d.items() if k in names}, raw=dict(d))  # type: ignore[no-any-return]


@dataclass
class License:
    id: str = ""
    project_id: str = ""
    policy_id: str = ""
    license_key: str = ""
    #: active, expired, revoked, suspended or pending_deactivation.
    status: str = ""
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    client_metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class LicensePage:
    licenses: list[License]
    #: The number of licenses in the project, not in this page.
    total: int


@dataclass
class Policy:
    id: str = ""
    name: str = ""
    license_type: str = ""
    expiry_mode: str = ""
    expiry_date: str | None = None
    expiry_days: int | None = None
    max_activations: int | None = None
    grace_period_hours: int | None = None
    created_at: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Activation:
    id: str = ""
    status: str = ""
    machine_id_hash: str = ""
    activated_at: str | None = None
    last_renewed_at: str | None = None
    deactivated_at: str | None = None
    seat_held_until: str | None = None
    sdk: Any = None
    metadata: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class AdminClient:
    """One project-scoped API key (``llk_live_...`` or ``llk_test_...``).
    Writes are never retried. A transport failure raises ``NetworkError``."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("AdminClient: api_key is required")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.headers["Authorization"] = f"Bearer {api_key}"

    def issue_license(
        self,
        policy_id: str,
        *,
        customer_email: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        client_metadata: Mapping[str, Any] | None = None,
    ) -> License:
        """Setting ``customer_email`` also emails the buyer their key, when
        the project allows it."""
        body: dict[str, Any] = {"policy_id": policy_id}
        if customer_email is not None:
            body["customer_email"] = customer_email
        if metadata is not None:
            body["metadata"] = metadata
        if client_metadata is not None:
            body["client_metadata"] = client_metadata
        return _build(License, self._call("POST", "/licenses", json=body))

    def list_licenses(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        customer_email: str | None = None,
        status: str | None = None,
    ) -> LicensePage:
        """Without ``limit`` (or with 0) returns every license in the project."""
        params = {
            k: v
            for k, v in {
                "limit": limit,
                "offset": offset,
                "customer_email": customer_email,
                "status": status,
            }.items()
            if v
        }
        out = self._call("GET", "/licenses", params=params)
        return LicensePage([_build(License, d) for d in out["licenses"]], out["total"])

    def get_license(self, license_key: str) -> License:
        return _build(License, self._call("GET", _license_path(license_key)))

    def update_license(
        self,
        license_key: str,
        *,
        metadata: Mapping[str, Any] = UNSET,
        client_metadata: Mapping[str, Any] = UNSET,
        expires_at: datetime | str | None = UNSET,
    ) -> License:
        """Changes only the fields passed. ``metadata`` and ``client_metadata``
        replace the stored object wholesale; ``expires_at=None`` clears the
        expiry."""
        body: dict[str, Any] = {}
        if metadata is not UNSET:
            body["metadata"] = metadata
        if client_metadata is not UNSET:
            body["client_metadata"] = client_metadata
        if expires_at is not UNSET:
            body["expires_at"] = (
                expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
            )
        return _build(License, self._call("PATCH", _license_path(license_key), json=body))

    def revoke_license(self, license_key: str) -> None:
        self._call("DELETE", _license_path(license_key))

    def suspend_license(self, license_key: str) -> License:
        return _build(License, self._call("POST", _license_path(license_key, "suspend")))

    def reinstate_license(self, license_key: str) -> License:
        return _build(License, self._call("POST", _license_path(license_key, "reinstate")))

    def list_activations(self, license_key: str) -> list[Activation]:
        out = self._call("GET", _license_path(license_key, "activations"))
        return [_build(Activation, d) for d in out["activations"]]

    def release_activation(self, license_key: str, activation_id: str) -> None:
        """Frees one machine's seat."""
        self._call("DELETE", _license_path(license_key, "activations", activation_id))

    def resend_license_email(self, license_key: str) -> None:
        """Queues the license-key email to the buyer again."""
        self._call("POST", _license_path(license_key, "resend"))

    def list_policies(self) -> list[Policy]:
        """The project's policies, to resolve a ``policy_id`` for ``issue_license``."""
        return [_build(Policy, d) for d in self._call("GET", "/policies")["policies"]]

    def _call(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        try:
            resp = self._session.request(
                method,
                self._base_url + path,
                json=json,
                params=params,
                headers={"Accept": "application/json"},
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            raise errors.NetworkError(str(e)) from e

        if not 200 <= resp.status_code < 300:
            try:
                body = resp.json()
            except ValueError:
                body = None
            body = body if isinstance(body, dict) else {}
            raise AdminError(
                resp.status_code,
                body.get("error") or resp.reason or f"HTTP {resp.status_code}",
                body.get("code"),
            )
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as e:
            raise errors.ServerError(f"decode response: {e}") from e


def _license_path(key: str, *rest: str) -> str:
    return "/licenses/" + "/".join(quote(s, safe="") for s in (key, *rest))
