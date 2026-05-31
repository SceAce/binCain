import os
import subprocess
from pathlib import Path

import pytest

from bincain.run_profiles import build_connection_profiles, build_run_profiles, parse_remote_target, write_run_target_wrapper


def test_build_run_profiles_creates_raw_debug_and_fuzz_profiles(tmp_path: Path):
    binary = tmp_path / "chall"
    binary.write_bytes(b"\x7fELF")

    profiles = build_run_profiles(binary)

    assert profiles["schema"] == "bincain.run_profiles.v1"
    assert profiles["default"] == "raw"
    assert {"raw", "debug", "fuzz"}.issubset(profiles["profiles"])


def test_build_run_profiles_adds_qemu_profiles_for_non_native_targets(tmp_path: Path):
    binary = tmp_path / "chall"
    binary.write_bytes(b"\x7fELF")

    profiles = build_run_profiles(binary, arch="mipsel", native=False, sysroot=tmp_path / "sysroot")

    assert profiles["default"] == "qemu"
    assert profiles["profiles"]["qemu"]["argv"][:3] == ["qemu-mipsel", "-L", str(tmp_path / "sysroot")]
    assert profiles["profiles"]["qemu-debug"]["argv"][:5] == ["qemu-mipsel", "-g", "1234", "-L", str(tmp_path / "sysroot")]


def test_build_connection_profiles_parses_remote_target():
    profiles = build_connection_profiles(remote="ctf.example:31337")

    assert profiles["profiles"]["remote"]["host"] == "ctf.example"
    assert profiles["profiles"]["remote"]["port"] == 31337


def test_parse_remote_target_rejects_invalid_values():
    with pytest.raises(ValueError):
        parse_remote_target("missing-port")


def test_write_run_target_wrapper_uses_profile_argument(tmp_path: Path):
    wrapper = write_run_target_wrapper(tmp_path / "scripts", tmp_path / "findings" / "run_profiles.json")

    text = wrapper.read_text()
    assert "--profile" in text
    assert "run_profiles.json" in text
    assert os.access(wrapper, os.X_OK)


def test_run_target_wrapper_preserves_stdin_for_target(tmp_path: Path):
    profiles_path = tmp_path / "findings" / "run_profiles.json"
    profiles_path.parent.mkdir()
    profiles_path.write_text(
        '{"schema":"bincain.run_profiles.v1","default":"raw","profiles":{"raw":{"argv":["/bin/cat"],"env":{}}}}'
    )
    wrapper = write_run_target_wrapper(tmp_path / "scripts", profiles_path)

    result = subprocess.run(
        [str(wrapper), "--profile", "raw"],
        input=b"stdin-survives\n",
        capture_output=True,
        check=True,
    )

    assert result.stdout == b"stdin-survives\n"


def test_run_target_wrapper_uses_default_profile_when_omitted(tmp_path: Path):
    profiles_path = tmp_path / "findings" / "run_profiles.json"
    profiles_path.parent.mkdir()
    profiles_path.write_text(
        '{"schema":"bincain.run_profiles.v1","default":"qemu","profiles":{"qemu":{"argv":["/bin/cat"],"env":{}}}}'
    )
    wrapper = write_run_target_wrapper(tmp_path / "scripts", profiles_path)

    result = subprocess.run(
        [str(wrapper)],
        input=b"default-profile\n",
        capture_output=True,
        check=True,
    )

    assert result.stdout == b"default-profile\n"
