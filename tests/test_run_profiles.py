import os
from pathlib import Path

from bincain.run_profiles import build_run_profiles, write_run_target_wrapper


def test_build_run_profiles_creates_raw_debug_and_fuzz_profiles(tmp_path: Path):
    binary = tmp_path / "chall"
    binary.write_bytes(b"\x7fELF")

    profiles = build_run_profiles(binary)

    assert profiles["schema"] == "bincain.run_profiles.v1"
    assert profiles["default"] == "raw"
    assert {"raw", "debug", "fuzz"}.issubset(profiles["profiles"])


def test_write_run_target_wrapper_uses_profile_argument(tmp_path: Path):
    wrapper = write_run_target_wrapper(tmp_path / "scripts", tmp_path / "findings" / "run_profiles.json")

    text = wrapper.read_text()
    assert "--profile" in text
    assert "run_profiles.json" in text
    assert os.access(wrapper, os.X_OK)
