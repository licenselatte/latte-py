"""Isolated chain-verification and signature-verification tests: build a
minimal cert chain in-process (independent of the shared fixtures /
generator) and exercise valid chains, tampered signatures, wrong keys,
broken intermediate links, and the documented cross-checks.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from latte import errors, verify
from latte.domain import CertChain

ISSUER = "licenselatte"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign_jwt(priv: Ed25519PrivateKey, claims: dict) -> str:
    header = _b64url(b'{"alg":"EdDSA","typ":"JWT"}')
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = priv.sign(signing_input)
    return f"{header}.{payload}.{_b64url(sig)}"


def hexpub(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes_raw().hex()


class Chain:
    def __init__(self, now: int):
        self.master = Ed25519PrivateKey.generate()
        self.submaster = Ed25519PrivateKey.generate()
        self.project = Ed25519PrivateKey.generate()
        self.daily = Ed25519PrivateKey.generate()

        submaster_cert = sign_jwt(
            self.master,
            {"iss": ISSUER, "iat": now - 1_000_000, "exp": now + 1_000_000, "spk": hexpub(self.submaster)},
        )
        project_cert = sign_jwt(
            self.submaster,
            {
                "iss": ISSUER, "iat": now - 500_000, "exp": now + 500_000,
                "ppk": hexpub(self.project), "pid": "proj_1",
            },
        )
        daily_cert = sign_jwt(
            self.project,
            {"iss": ISSUER, "iat": now - 86_400, "exp": now + 86_400, "dpk": hexpub(self.daily)},
        )
        self.chain = CertChain(submaster=submaster_cert, project=project_cert, daily=daily_cert)


def activation_claims(now: int) -> dict:
    return {
        "iss": ISSUER, "sub": "KEY", "aid": "ACT1", "pid": "proj_1", "mid": "machine-1",
        "ltype": "expiring", "iat": now, "exp": now + 1_000_000, "grc": 7 * 86_400,
    }


def test_valid_chain_and_signature_is_accepted():
    now = 10_000_000
    c = Chain(now)
    token = sign_jwt(c.daily, activation_claims(now))
    lic = verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))
    assert lic.key == "KEY"
    assert lic.project_id == "proj_1"


def test_tampered_signature_is_rejected():
    now = 10_000_000
    c = Chain(now)
    token = sign_jwt(c.daily, activation_claims(now)) + "x"
    with pytest.raises(errors.VerifyError):
        verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))


def test_wrong_master_key_is_rejected():
    now = 10_000_000
    c = Chain(now)
    token = sign_jwt(c.daily, activation_claims(now))
    wrong_master = Ed25519PrivateKey.generate()
    with pytest.raises(errors.InvalidSignatureError):
        verify.verify_activation_at(wrong_master.public_key(), token, c.chain, float(now))


def test_broken_intermediate_link_is_rejected():
    now = 10_000_000
    c = Chain(now)
    rogue = Ed25519PrivateKey.generate()
    c.chain = CertChain(
        submaster=c.chain.submaster,
        project=sign_jwt(
            rogue,
            {
                "iss": ISSUER, "iat": now - 500_000, "exp": now + 500_000,
                "ppk": hexpub(c.project), "pid": "proj_1",
            },
        ),
        daily=c.chain.daily,
    )
    token = sign_jwt(c.daily, activation_claims(now))
    with pytest.raises(errors.InvalidSignatureError):
        verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))


def test_project_id_cross_check_enforced():
    now = 10_000_000
    c = Chain(now)
    claims = activation_claims(now)
    claims["pid"] = "some-other-project"
    token = sign_jwt(c.daily, claims)
    with pytest.raises(errors.ChainInconsistentError):
        verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))


def test_daily_cert_missing_exp_is_rejected():
    now = 10_000_000
    c = Chain(now)
    c.chain = CertChain(
        submaster=c.chain.submaster,
        project=c.chain.project,
        daily=sign_jwt(c.project, {"iss": ISSUER, "iat": now - 86_400, "dpk": hexpub(c.daily)}),
    )
    token = sign_jwt(c.daily, activation_claims(now))
    with pytest.raises(errors.MissingClaimError):
        verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))


def test_cert_iat_in_future_rejected_with_zero_leeway():
    now = 10_000_000
    c = Chain(now)
    token = sign_jwt(c.daily, activation_claims(now))
    skewed_now = float(now - 86_400 - 10)  # before daily cert's own iat
    with pytest.raises(errors.NotYetValidError):
        verify.verify_activation_at(c.master.public_key(), token, c.chain, skewed_now)


def test_activation_future_iat_tolerated_by_infinite_leeway():
    now = 10_000_000
    c = Chain(now)
    claims = activation_claims(now)
    claims["iat"] = now + 3600  # 1h in the future relative to `now` below
    token = sign_jwt(c.daily, claims)
    # Chain (cert) validity windows comfortably cover `now`; only the
    # activation JWT's own iat is "in the future", tolerated by the
    # activation token's effectively-infinite leeway.
    verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))


def test_grace_period_exceeding_90_day_ceiling_rejected():
    now = 10_000_000
    c = Chain(now)
    claims = activation_claims(now)
    claims["grc"] = 91 * 86_400
    token = sign_jwt(c.daily, claims)
    with pytest.raises(errors.ChainInconsistentError):
        verify.verify_activation_at(c.master.public_key(), token, c.chain, float(now))


def test_malformed_token_rejected():
    now = 10_000_000
    c = Chain(now)
    with pytest.raises(errors.MalformedTokenError):
        verify.verify_activation_at(c.master.public_key(), "not-a-jwt", c.chain, float(now))
