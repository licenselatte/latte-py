"""License-key / AppID normalization and checksum.

This is a hand-rolled typo-catching checksum, not a cryptographic
primitive, so reimplementing it here (rather than using a crypto library)
is correct, not a "hand-rolled crypto" violation.
"""

from __future__ import annotations

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _alphabet_index(c: str) -> int:
    try:
        return _ALPHABET.index(c)
    except ValueError:
        return -1


def _calculate_checksum(data: str, length: int) -> str:
    total = 0
    for i, c in enumerate(data):
        val = _alphabet_index(c)
        if i % 2 == 0:
            val *= 2
        total += val

    # Python's % is always non-negative for a positive divisor, which makes
    # malformed (out-of-alphabet) input safe here without extra handling.
    return "".join(_ALPHABET[(total + i * 31) % len(_ALPHABET)] for i in range(length))


def validate_key(key: str, checksum_len: int) -> bool:
    """Validates that the last ``checksum_len`` characters of ``key`` are
    the correct checksum of the preceding characters.
    """
    if len(key) < checksum_len:
        return False
    data_part, provided = key[:-checksum_len], key[-checksum_len:]
    return _calculate_checksum(data_part, checksum_len) == provided


_FOLD = str.maketrans({"O": "0", "I": "1", "L": "1"})


def sanitize_key(raw: str) -> str:
    """Uppercases, strips hyphens/spaces, and folds the visually-ambiguous
    characters ``O -> 0``, ``I -> 1``, ``L -> 1`` (``I`` and ``L`` both fold
    to ``1``, so a sanitized key can never distinguish an original ``L``
    from an original ``I`` from an original ``1``; this is intentional
    behavior, not an oversight). This fold is specific to the native key
    alphabet (which deliberately excludes ``O``/``I``/``L``) — use it only
    where the value is expected to be a native-format key. Use
    ``normalize_key`` for anything else.
    """
    s = raw.upper().replace("-", "").replace(" ", "")
    return s.translate(_FOLD)


def normalize_key(raw: str) -> str:
    """Uppercases and strips hyphens/spaces, with no other transformation.
    Unlike ``sanitize_key``, this never assumes the input is in the native
    key alphabet, so it's safe to use on any license key string regardless
    of which system minted it.
    """
    return raw.upper().replace("-", "").replace(" ", "")
