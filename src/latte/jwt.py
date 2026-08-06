"""Minimal EdDSA/Ed25519 JWT compact-serialization handling.

The whole chain uses exactly one JWA algorithm (``"EdDSA"``, RFC 8037, pure
Ed25519, never prehashed HashEdDSA), one serialization (compact), and a
fixed set of claims per JWT "kind". There is no reason to depend on a
general JWT library for four call sites with one fixed algorithm; the only
cryptographic primitive used is ``cryptography``'s Ed25519 signature
verification (audited hazmat primitive, not hand-rolled).
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import errors


@dataclass
class ParsedJwt:
    claims: dict[str, Any]


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def parse_and_verify(
    token: str,
    pub_key: Ed25519PublicKey,
    expected_issuer: str,
    now: float,
    leeway_secs: float | None = 0,
) -> ParsedJwt:
    """Parses and Ed25519-verifies a compact JWT, then validates ``iss`` and,
    with the given leeway (zero by default), ``iat``/``exp``/``nbf`` if
    present.

    Zero leeway is used for cert verification: submaster/project/daily
    certs get no clock-skew tolerance at all. Pass ``leeway_secs=None`` for
    the activation-token parse, which uses an effectively-infinite leeway:
    expiry for that JWT is instead entirely the responsibility of the
    hand-rolled grace-period math in validate.py.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise errors.MalformedTokenError(
            f"expected 3 dot-separated parts, got {len(parts)}"
        )
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as e:  # noqa: BLE001 - any decode/parse failure is "malformed"
        raise errors.MalformedTokenError(f"header: {e}") from e
    if header.get("alg") != "EdDSA":
        raise errors.MalformedTokenError(f"unexpected alg: {header.get('alg')!r}")

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as e:  # noqa: BLE001
        raise errors.MalformedTokenError(f"payload: {e}") from e
    if not isinstance(claims, dict):
        raise errors.MalformedTokenError("payload is not a JSON object")

    try:
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as e:  # noqa: BLE001
        raise errors.MalformedTokenError(f"signature: {e}") from e
    if len(sig_bytes) != 64:
        raise errors.MalformedTokenError(f"signature is not 64 bytes, got {len(sig_bytes)}")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        pub_key.verify(sig_bytes, signing_input)
    except InvalidSignature as e:
        raise errors.InvalidSignatureError() from e

    if claims.get("iss") != expected_issuer:
        raise errors.WrongIssuerError()

    if leeway_secs is not None:
        _check_time_claims(claims, now, leeway_secs)

    return ParsedJwt(claims=claims)


def _check_time_claims(claims: dict[str, Any], now: float, leeway_secs: float) -> None:
    iat = claims.get("iat")
    if isinstance(iat, (int, float)) and iat > now + leeway_secs:
        raise errors.NotYetValidError()
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now + leeway_secs:
        raise errors.NotYetValidError()
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp < now - leeway_secs:
        raise errors.ExpiredError()


def current_unix_time() -> float:
    return time.time()
