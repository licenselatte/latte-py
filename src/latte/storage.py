"""On-disk caching for an activated license, so an application doesn't
have to hit the network on every startup.

The file is a small flat JSON record::

    {
      "timestamp": 1700000000,
      "token": "<activation JWT>",
      "submaster": "<submaster cert JWT>",
      "project": "<project cert JWT>",
      "daily": "<daily cert JWT>"
    }

``timestamp`` (unix seconds, set at save time) is metadata for a human
reading the file, not used by anything in this package: the token's own
``iat``/``exp`` claims are what govern expiry and grace-period math.

Every function here treats "can't read/parse the cache" and "no cache
exists" identically: both just mean the caller falls back to activating
over the network. A corrupted or unreadable file is never a hard error.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import platformdirs

from .domain import CertChain


def default_path(project_key: str) -> Path:
    """The default cache file location for a given project key: a
    ``licenselatte`` folder under the OS's per-user config directory
    (chosen over a cache directory because it isn't subject to being
    cleared by disk-cleanup tools; losing this file just means one extra
    activation call, but there's no reason to invite that), named after
    the 32-char project key segment so multiple projects on the same
    machine don't collide.
    """
    return Path(platformdirs.user_config_dir("LicenseLatte")) / f"{project_key}.json"


def load(path: Path) -> tuple[str, CertChain] | None:
    """Reads and parses the cache file at ``path``. Returns ``None`` on any
    problem at all (missing file, permission error, corrupt/foreign JSON),
    since every caller's response to a cache miss and a cache error is the
    same: proceed as if nothing was cached.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None

    try:
        return data["token"], CertChain(
            submaster=data["submaster"], project=data["project"], daily=data["daily"]
        )
    except (KeyError, TypeError):
        return None


def save(path: Path, token: str, chain: CertChain) -> None:
    """Writes ``token``/``chain`` to the cache file at ``path``, creating
    parent directories as needed. Writes to a temporary file in the same
    directory first and renames it into place, so a process interrupted
    mid-write (or a crash) can never leave a half-written, corrupt cache
    file behind: readers only ever see the previous complete version or
    the new one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": int(time.time()),
        "token": token,
        "submaster": chain.submaster,
        "project": chain.project,
        "daily": chain.daily,
    }

    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(record))
    os.replace(tmp_path, path)


def clear(path: Path) -> None:
    """Deletes the cache file at ``path``, if it exists. Used to drop a
    token the server has told us is no longer valid, so a future
    ``activate``/``check`` doesn't keep finding it. Missing-file is not an
    error.
    """
    path.unlink(missing_ok=True)
