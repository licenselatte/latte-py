"""Python SDK for LicenseLatte license activation and offline verification.

``Sdk`` activates and renews licenses over the network, with an optional
on-disk cache so a valid activation survives across process restarts
without a network call.

IMPORTANT: read the "Threat Model" section of README.md before relying on
this package for anything security-sensitive: Python bytecode is trivially
readable and patchable, so this package provides the same *cryptographic
correctness* as the compiled SDKs but not the same tamper resistance.
"""

from __future__ import annotations

from . import appid, domain, entitlements, errors, http, key, validate, verify
from .domain import CertChain
from .entitlements import UNLIMITED, EntitlementValue
from .errors import (
    InvalidKeyError,
    InvalidProjectKeyError,
    LatteError,
    LicenseExpiredError,
    LicenseNotFoundError,
    NetworkError,
    NotActivatedError,
    SeatLimitError,
    ServerError,
    ValidateError,
    VerifyError,
)
from .http import Config, Sdk
from .license import PublicLicense, check_license, check_license_at

__all__ = [
    "appid",
    "domain",
    "entitlements",
    "errors",
    "http",
    "key",
    "validate",
    "verify",
    "CertChain",
    "Config",
    "EntitlementValue",
    "UNLIMITED",
    "Sdk",
    "PublicLicense",
    "check_license_at",
    "check_license",
    "ValidateError",
    "VerifyError",
    "LatteError",
    "InvalidKeyError",
    "LicenseExpiredError",
    "NotActivatedError",
    "SeatLimitError",
    "LicenseNotFoundError",
    "InvalidProjectKeyError",
    "NetworkError",
    "ServerError",
]
