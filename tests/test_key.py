from __future__ import annotations

import pytest

from latte import appid, errors, key


def test_sanitize_folds_ambiguous_chars():
    assert key.sanitize_key("ab-cd IL o") == "ABCD110"


def test_checksum_round_trips():
    data = "AHAK85389VQYXYB6S4BW66SKE53TWVT"
    checksum = key._calculate_checksum(data, 4)
    assert key.validate_key(data + checksum, 4)
    assert not key.validate_key(data + "XXXX", 4)


def test_checksum_survives_out_of_alphabet_input():
    # Go's naive `%` could go negative and panic indexing the alphabet on
    # out-of-alphabet input; this must degrade to "no match", not crash.
    assert key.validate_key("!!!!not-valid-alphabet!!!!", 4) in (True, False)


def test_parse_app_id_happy_path():
    data = "AHAK85389VQYXYB6S4BW66SKE53T"
    checksum = key._calculate_checksum(data, 4)
    parsed = appid.parse_app_id(f"pk_live_{data}{checksum}")
    assert parsed.env == "live"
    assert parsed.base_url == "https://api.licenselatte.com"


def test_parse_app_id_local_environment_is_supported():
    data = "AHAK85389VQYXYB6S4BW66SKE53T"
    checksum = key._calculate_checksum(data, 4)
    parsed = appid.parse_app_id(f"pk_local_{data}{checksum}")
    assert parsed.base_url == "http://localhost:8080"


def test_parse_app_id_bad_checksum_rejected():
    with pytest.raises(errors.InvalidChecksumError):
        appid.parse_app_id("pk_live_AHAK85389VQYXYB6S4BW66SKE53TXXXX")


def test_parse_app_id_unknown_environment_rejected():
    data = "AHAK85389VQYXYB6S4BW66SKE53T"
    checksum = key._calculate_checksum(data, 4)
    with pytest.raises(errors.UnknownEnvironmentError):
        appid.parse_app_id(f"pk_staging_{data}{checksum}")
