"""``AppId`` (``pk_{env}_{32-char key}``) parsing and validation.

Includes the undocumented-but-real ``local`` environment.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import errors
from .key import validate_key

_BASE_URLS = {
    "live": "https://api.licenselatte.com",
    "test": "https://test.api.licenselatte.com",
    "local": "http://localhost:8080",
}


@dataclass(frozen=True)
class AppId:
    env: str
    key: str  # the 32-character key segment, including its trailing 4-char checksum

    @property
    def base_url(self) -> str:
        return _BASE_URLS[self.env]


def parse_app_id(app_id: str) -> AppId:
    parts = app_id.split("_")
    if len(parts) != 3 or parts[0] != "pk":
        raise errors.InvalidAppIdFormatError()

    env = parts[1]
    if env not in _BASE_URLS:
        raise errors.UnknownEnvironmentError(env)

    key = parts[2]
    if len(key) != 32:
        raise errors.InvalidKeySegmentError()
    if not validate_key(key, 4):
        raise errors.InvalidChecksumError()

    return AppId(env=env, key=key)
