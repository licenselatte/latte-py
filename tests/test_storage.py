from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from latte import storage
from latte.domain import CertChain


def _chain() -> CertChain:
    return CertChain(submaster="s", project="p", daily="d")


def test_round_trips_through_save_and_load(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    storage.save(path, "the-token", _chain())

    token, chain = storage.load(path)  # type: ignore[misc]

    assert token == "the-token"
    assert chain.submaster == "s"
    assert chain.project == "p"
    assert chain.daily == "d"


def test_writes_snake_case_json(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    storage.save(path, "the-token", _chain())

    data = json.loads(path.read_text())
    assert set(data.keys()) == {"timestamp", "token", "submaster", "project", "daily"}


def test_load_returns_none_for_a_missing_file(tmp_path: Path) -> None:
    assert storage.load(tmp_path / "does-not-exist.json") is None


def test_load_returns_none_for_corrupt_json(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    path.write_text("not json")
    assert storage.load(path) is None


def test_load_returns_none_for_json_missing_expected_fields(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"unrelated": "data"}))
    assert storage.load(path) is None


def test_save_creates_missing_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "token.json"
    storage.save(path, "the-token", _chain())
    assert storage.load(path) is not None


def test_save_overwrites_an_existing_file_without_leaving_a_temp_file_behind(
    tmp_path: Path,
) -> None:
    path = tmp_path / "token.json"
    storage.save(path, "first", _chain())
    storage.save(path, "second", _chain())

    token, _ = storage.load(path)  # type: ignore[misc]
    assert token == "second"
    assert list(tmp_path.glob("*.tmp")) == []


def test_overlapping_saves_never_leave_a_corrupt_cache(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    big = CertChain(submaster="s" * 200_000, project="p" * 200_000, daily="d" * 200_000)
    small = _chain()

    def run(
        barrier: threading.Barrier, errors: list[OSError], token: str, chain: CertChain
    ) -> None:
        barrier.wait()
        try:
            storage.save(path, token, chain)
        except OSError as e:
            errors.append(e)

    for _ in range(200):
        barrier = threading.Barrier(2)
        errors: list[OSError] = []
        threads = [
            threading.Thread(target=run, args=(barrier, errors, "big", big)),
            threading.Thread(target=run, args=(barrier, errors, "small", small)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        loaded = storage.load(path)
        assert loaded is not None
        token, chain = loaded
        assert (token, chain) in [("big", big), ("small", small)]
        assert list(tmp_path.glob("*.tmp")) == []


def test_save_removes_its_temp_file_when_the_rename_fails(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    path.mkdir()  # os.replace of a file over a directory fails

    with pytest.raises(OSError):
        storage.save(path, "the-token", _chain())

    assert list(tmp_path.glob("*.tmp")) == []


def test_clear_removes_the_file(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    storage.save(path, "the-token", _chain())

    storage.clear(path)
    assert storage.load(path) is None


def test_clear_on_a_missing_file_is_not_an_error(tmp_path: Path) -> None:
    storage.clear(tmp_path / "does-not-exist.json")  # must not raise
