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

from importlib.metadata import PackageNotFoundError, version as _version

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

try:
    #: The installed distribution's version. Written by setuptools-scm from
    #: the git tag at build time, so there is no literal to keep in sync --
    #: see pyproject.toml's [tool.setuptools_scm].
    __version__ = _version("latte-py")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    # Imported without being installed (a bare sys.path checkout). There is
    # no distribution metadata to read, and guessing from the working tree
    # would be worse than admitting we do not know.
    __version__ = "0.0.0.dev0"

__all__ = [
    "__version__",
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
