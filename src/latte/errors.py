"""Error types.

VerifyError's subclasses are a convenience for callers: every fixture
that expects a "verify"-stage rejection accepts any VerifyError subclass.
ValidateError's subclasses are distinct sentinel-style errors and must not
be collapsed or renamed.
"""

from __future__ import annotations


class VerifyError(Exception):
    """Base class for chain/signature verification failures."""


class MalformedTokenError(VerifyError):
    """The JWT was not well-formed."""


class InvalidSignatureError(VerifyError):
    """The Ed25519 signature did not verify."""


class MissingClaimError(VerifyError):
    """A required claim was missing or had the wrong type."""

    def __init__(self, claim: str) -> None:
        super().__init__(f"missing claim: {claim}")
        self.claim = claim


class InvalidClaimError(VerifyError):
    """A claim was present but structurally invalid."""

    def __init__(self, claim: str, reason: str) -> None:
        super().__init__(f"invalid claim {claim}: {reason}")
        self.claim = claim
        self.reason = reason


class WrongIssuerError(VerifyError):
    """``iss`` didn't match the expected issuer."""


class NotYetValidError(VerifyError):
    """The JWT's ``iat``/``nbf`` is after the verifier's current time (zero leeway)."""


class ExpiredError(VerifyError):
    """The JWT's ``exp`` is before the verifier's current time (zero leeway)."""


class ChainInconsistentError(VerifyError):
    """A cross-check between two certs in the chain failed."""


class ValidateError(Exception):
    """Base class for grace-period / offline validation failures."""


class HardExpiredError(ValidateError):
    """``now > expires_at``."""


class GraceExpiredError(ValidateError):
    """``now > issued_at + grace_period``, but not yet past ``expires_at``."""


class LicenseTooOldError(ValidateError):
    """``now - issued_at > 365 days``, independent of expiry/grace."""


class MachineIdMismatchError(ValidateError):
    """The caller-supplied machine ID doesn't match the license's ``mid`` claim."""


class InvalidFieldsError(ValidateError):
    """One of issued_at/expires_at/grace_period is missing or inconsistent."""


class AppIdError(Exception):
    """Base class for AppID parsing/checksum failures."""


class InvalidAppIdFormatError(AppIdError):
    pass


class UnknownEnvironmentError(AppIdError):
    def __init__(self, env: str) -> None:
        super().__init__(f"unknown environment: {env}")
        self.env = env


class InvalidKeySegmentError(AppIdError):
    pass


class InvalidChecksumError(AppIdError):
    pass


class LatteError(Exception):
    """Base class for errors raised by ``Sdk`` (``activate``, ``renew``,
    ``check``).

    Distinct from ``VerifyError``/``ValidateError`` (chain/grace-period
    failures on an already-fetched token): these are failures of
    ``Sdk``'s own calls: bad key format, transport failure, a
    non-2xx/malformed server response, or (for ``check``) no usable cached
    license.
    """


class InvalidKeyError(LatteError):
    """The license key's format or checksum is invalid, or its short_id
    doesn't match this SDK's project key. Never reaches the network."""


class LicenseExpiredError(LatteError):
    """The license is past its hard expiry, from a 403 response
    (``activate``/``renew``) or a cached token (``check``)."""


class NotActivatedError(LatteError):
    """No usable license is currently active on this machine: nothing is
    cached, the cache is unreadable/tampered, or it's valid but rejected
    for a reason other than hard expiry (out of grace, too old, wrong
    machine). Only raised by ``check``."""


class SeatLimitError(LatteError):
    """Server returned 409 (activation seat limit reached)."""


class LicenseNotFoundError(LatteError):
    """Server returned 404 (license not found)."""


class InvalidProjectKeyError(LatteError):
    """Server returned 401 (invalid project key)."""


class NetworkError(LatteError):
    """Transport-level failure (DNS, TCP, timeout): the request never got
    a response."""


class ServerError(LatteError):
    """Non-2xx response with no specific sentinel, a malformed/empty
    response body, or a server-issued token that failed local chain
    verification/grace-period validation."""
