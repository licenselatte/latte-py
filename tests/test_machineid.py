"""Tests for ``latte.machineid``: the shared vectors through
``protected_id``, the ioreg parser against fixture output, the platform
reader on the host running the suite, and how ``Sdk`` picks its raw ID."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from latte import errors, machineid
from latte.http import Config, Sdk

VECTORS = Path(__file__).parent.parent / "testdata" / "machine_id.json"
APP_ID = "pk_test_AHAK85389VQYXYB6S4BW66SKE53TWVTS"

IOREG_OUTPUT = """\
+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000237, registered, matched, active, busy 0 (12 ms), retain 39>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4B4E32"
      "manufacturer" = <"Apple Inc.">
    }
"""


def _cases() -> list[dict[str, str]]:
    cases: list[dict[str, str]] = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]
    return cases


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["app_id"])
def test_protected_id_matches_the_shared_vectors(case: dict[str, str]) -> None:
    got = machineid.protected_id(case["raw_machine_id"], case["app_id"])
    assert got == case["expect_machine_id"]


def test_extract_ioreg_uuid_reads_the_platform_uuid() -> None:
    raw = machineid._extract_ioreg_uuid(IOREG_OUTPUT)
    assert raw == "4C4C4544-0042-3510-8051-B4C04F4B4E32"


def test_extract_ioreg_uuid_skips_lines_that_do_not_split_in_two() -> None:
    output = '"IOPlatformUUID" malformed\n  "IOPlatformUUID" = "ABC"\n'
    assert machineid._extract_ioreg_uuid(output) == "ABC"


def test_extract_ioreg_uuid_without_a_uuid_raises() -> None:
    with pytest.raises(errors.MachineIdError):
        machineid._extract_ioreg_uuid('"IOPlatformSerialNumber" = "C02"\n')


def test_linux_reader_falls_back_to_the_second_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    present = tmp_path / "machine-id"
    present.write_text("b08f1a2c3d4e5f60718293a4b5c6d7e8\n", encoding="utf-8")
    raw = machineid._read_first_file((str(missing), str(present)))
    assert raw == "b08f1a2c3d4e5f60718293a4b5c6d7e8"


def test_linux_reader_skips_an_empty_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.write_text("\n", encoding="utf-8")
    present = tmp_path / "machine-id"
    present.write_text("abc", encoding="utf-8")
    assert machineid._read_first_file((str(empty), str(present))) == "abc"


@pytest.mark.skipif(
    not (sys.platform in ("darwin", "win32") or sys.platform.startswith("linux")),
    reason="no platform machine ID reader exercised on this OS",
)
def test_read_platform_id_returns_a_value_on_this_host() -> None:
    try:
        raw = machineid.read_platform_id()
    except errors.MachineIdError as e:
        # A minimal container may have no machine ID at all.
        pytest.skip(f"no machine ID on this host: {e}")
    assert raw != ""
    assert raw == raw.strip()


def test_sdk_derives_from_the_supplied_raw_id() -> None:
    sdk = Sdk(Config(app_id=APP_ID, machine_id="seat-42", cache=False))
    assert sdk.machine_id == machineid.protected_id("seat-42", APP_ID)


def test_sdk_reads_the_platform_id_when_none_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(machineid, "read_platform_id", lambda: "platform-raw")
    for supplied in (None, ""):
        sdk = Sdk(Config(app_id=APP_ID, machine_id=supplied, cache=False))
        assert sdk.machine_id == machineid.protected_id("platform-raw", APP_ID)


def test_sdk_raises_at_construction_without_any_machine_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable() -> str:
        raise errors.MachineIdError("cannot read the platform machine ID")

    monkeypatch.setattr(machineid, "read_platform_id", unreadable)
    with pytest.raises(errors.MachineIdError):
        Sdk(Config(app_id=APP_ID, cache=False))
