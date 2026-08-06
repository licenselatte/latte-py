"""Certificate chain verification: Master -> Submaster -> Project -> Daily
-> activation token.

Includes the chain cross-checks and one intentionally-preserved quirk:
see the comment at that check below before "fixing" it.
"""

from __future__ import annotations

import binascii
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import errors
from .domain import CertChain, License
from .jwt import parse_and_verify

_ISSUER = "licenselatte"
_MAX_GRACE_PERIOD_SECS = 90 * 24 * 60 * 60


def _pub_key_from_cert(claims: dict[str, Any], field: str) -> Ed25519PublicKey:
    hex_str = claims.get(field)
    if not isinstance(hex_str, str):
        raise errors.MissingClaimError(field)
    try:
        raw = bytes.fromhex(hex_str)
    except (ValueError, binascii.Error) as e:
        raise errors.InvalidClaimError(field, f"not valid hex: {e}") from e
    if len(raw) != 32:
        raise errors.InvalidClaimError(field, f"must be 32 bytes, got {len(raw)}")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as e:  # noqa: BLE001
        raise errors.InvalidClaimError(field, str(e)) from e


def verify_activation_at(
    master_pub: Ed25519PublicKey,
    token: str,
    chain: CertChain,
    now: float,
) -> License:
    """Verifies the full chain and the activation token, evaluating
    time-based claims as of ``now`` (unix seconds).

    Production callers should pass ``time.time()``; tests pass a fixture's
    pinned ``now`` so results are reproducible.
    """
    # Step 1: submaster cert, signed by master.
    sub = parse_and_verify(chain.submaster, master_pub, _ISSUER, now)
    submaster_pub = _pub_key_from_cert(sub.claims, "spk")

    # Step 2: project cert, signed by submaster.
    proj = parse_and_verify(chain.project, submaster_pub, _ISSUER, now)
    project_pub = _pub_key_from_cert(proj.claims, "ppk")

    # Step 3: daily cert, signed by project key.
    daily = parse_and_verify(chain.daily, project_pub, _ISSUER, now)
    daily_pub = _pub_key_from_cert(daily.claims, "dpk")

    # Step 4: activation JWT, signed by the daily key. An effectively-infinite
    # leeway is applied here: its own iat/exp/nbf are not authoritative;
    # the grace-period math in validate.py is.
    activation = parse_and_verify(token, daily_pub, _ISSUER, now, leeway_secs=None)
    claims = activation.claims

    key = claims.get("sub", "")
    activation_id = claims.get("aid", "")
    project_id = claims.get("pid", "")
    machine_id = claims.get("mid", "")
    license_type = claims.get("ltype", "")

    grc = claims.get("grc", 0)
    grace_period_secs = max(float(grc) if isinstance(grc, (int, float)) else 0, 0)
    iat = float(claims["iat"]) if isinstance(claims.get("iat"), (int, float)) else 0.0
    exp = float(claims["exp"]) if isinstance(claims.get("exp"), (int, float)) else 0.0

    metadata: dict[str, str] = {}
    pmd = claims.get("pmd")
    if isinstance(pmd, dict):
        for k, v in pmd.items():
            if isinstance(v, str):
                metadata[k] = v

    # Cross-check: project cert's own pid (if present) must agree with the
    # activation JWT's pid.
    pid_in_cert = proj.claims.get("pid")
    if isinstance(pid_in_cert, str) and pid_in_cert and pid_in_cert != project_id:
        raise errors.ChainInconsistentError(
            f"project_id mismatch between activation JWT ({project_id}) "
            f"and project cert ({pid_in_cert})"
        )

    # Daily cert's iat/exp are required (not just optional claims).
    daily_iat = daily.claims.get("iat")
    if not isinstance(daily_iat, (int, float)):
        raise errors.MissingClaimError("iat")
    daily_exp = daily.claims.get("exp")
    if not isinstance(daily_exp, (int, float)):
        raise errors.MissingClaimError("exp")

    # Cross-check: activation iat must not precede the daily cert's own iat
    # (an activation can't have been issued before its signer existed).
    if iat < daily_iat:
        raise errors.ChainInconsistentError("activation JWT iat is before daily cert iat")

    # Cross-check intended to ensure the activation doesn't outlive the
    # daily cert that signed it. This compares the activation's IssuedAt
    # against the daily cert's exp, not the activation's own ExpiresAt as
    # the error message below might suggest. This is intentional: do not
    # change this to compare `exp` without explicit sign-off, since it
    # changes accept/reject outcomes.
    if iat > daily_exp:
        raise errors.ChainInconsistentError("activation JWT iat is after daily cert exp")

    # Grace period ceiling: no lower bound is enforced anywhere.
    if grace_period_secs > _MAX_GRACE_PERIOD_SECS:
        raise errors.ChainInconsistentError(f"grace period too long: {grace_period_secs}s")

    return License(
        key=key,
        activation_id=activation_id,
        project_id=project_id,
        machine_id=machine_id,
        issued_at=iat,
        expires_at=exp,
        grace_period_secs=grace_period_secs,
        license_type=license_type,
        metadata=metadata,
    )
