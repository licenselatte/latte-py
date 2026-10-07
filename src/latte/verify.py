"""Certificate chain verification: Master -> Submaster -> Project -> Daily
-> activation token.

Includes the chain cross-checks and one intentionally-preserved quirk:
see the comment at that check below before "fixing" it.
"""

from __future__ import annotations

import binascii
from collections.abc import Sequence
from typing import Any, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import errors
from .domain import CertChain, License
from .entitlements import decode_entitlements
from .jwt import ParsedJwt, parse_and_verify

_ISSUER = "licenselatte"
_MAX_GRACE_PERIOD_SECS = 90 * 24 * 60 * 60

# The Ed25519 master public keys a certificate chain may be rooted in. These
# are public keys, not secrets: they're meant to be embedded in every SDK.
# A chain is accepted if its submaster cert verifies under any one of them.
_MASTER_PUBLIC_KEYS_HEX = (
    # Old root, YubiKey 32493801.
    # Primary fingerprint 49C1CA77D17984E0D25C0994D626409AD567D479.
    # Kept until the submaster cert it signed expires on 2026-12-11.
    "6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb",
    # root-a, YubiKey 40127477.
    # Primary fingerprint B89594D5DD7B9213E5FC7DC27FC9430452C9F38D,
    # authentication subkey A53549AF5B5570F304D4342D702AEFFF07B512EF.
    "73358e45a5c77b7f7236d26f5a1756011b522d277bb19ac4869d2e88952705cd",
    # root-b, YubiKey 40127498.
    # Primary fingerprint A980BA5DD0B3831A4038D22C744D413D801A1AFA,
    # authentication subkey B217F9743D6FD3EB21FF87D83752947C4AD9CC5E.
    "4f9369b8a4a0fd9be67cd403e4ed92e0d45609772659be4a066c1a9c4eff43fe",
    # root-c, YubiKey 40127484.
    # Primary fingerprint 7F3CC680FF472FCF9A351CAF8204C38EAF10DA14,
    # authentication subkey 59282CA469B7E8168952E07476352E58361B3A92.
    "46d45bbc3280df763fcaf7a37055888eeefbb5781784c1f471f4f413d72b123f",
)

#: The master public keys ``Sdk`` verifies against. Pass this to
#: ``check_license``/``check_license_at``/``verify_activation_at`` when
#: re-verifying a token you store yourself.
MASTER_PUBLIC_KEYS: tuple[Ed25519PublicKey, ...] = tuple(
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(h)) for h in _MASTER_PUBLIC_KEYS_HEX
)

#: One master public key, or several of which any one may root the chain.
MasterKeys = Union[Ed25519PublicKey, Sequence[Ed25519PublicKey]]


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


def _verify_submaster(cert: str, master_pub: MasterKeys, now: float) -> ParsedJwt:
    """Verifies the submaster cert under the first master key it verifies
    under. If none does, raises the error from the first key tried.
    """
    keys = [master_pub] if isinstance(master_pub, Ed25519PublicKey) else list(master_pub)
    if not keys:
        raise ValueError("at least one master public key is required")
    first_error: errors.VerifyError | None = None
    for key in keys:
        try:
            return parse_and_verify(cert, key, _ISSUER, now)
        except errors.VerifyError as e:
            first_error = first_error or e
    assert first_error is not None
    raise first_error


def verify_activation_at(
    master_pub: MasterKeys,
    token: str,
    chain: CertChain,
    now: float,
) -> License:
    """Verifies the full chain and the activation token, evaluating
    time-based claims as of ``now`` (unix seconds).

    ``master_pub`` is one key or a sequence of them (``MASTER_PUBLIC_KEYS``
    is the set ``Sdk`` uses); the chain is accepted if its submaster cert
    verifies under any one.

    Production callers should pass ``time.time()``; tests pass a fixture's
    pinned ``now`` so results are reproducible.
    """
    # Step 1: submaster cert, signed by one of the master keys.
    sub = _verify_submaster(chain.submaster, master_pub, now)
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
    alias = claims.get("alias", "")
    activation_id = claims.get("aid", "")
    project_id = claims.get("pid", "")
    machine_id = claims.get("mid", "")
    license_type = claims.get("ltype", "")

    grc = claims.get("grc", 0)
    grace_period_secs = max(float(grc) if isinstance(grc, (int, float)) else 0, 0)
    iat = float(claims["iat"]) if isinstance(claims.get("iat"), (int, float)) else 0.0
    exp = float(claims["exp"]) if isinstance(claims.get("exp"), (int, float)) else 0.0

    entitlements = decode_entitlements(claims)

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
        alias=alias,
        activation_id=activation_id,
        project_id=project_id,
        machine_id=machine_id,
        issued_at=iat,
        expires_at=exp,
        grace_period_secs=grace_period_secs,
        license_type=license_type,
        metadata=metadata,
        entitlements=entitlements,
    )
