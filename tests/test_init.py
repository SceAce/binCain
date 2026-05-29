import json
import os
from pathlib import Path

from bincain.init import init_challenge


def test_init_challenge_writes_metadata_and_run_wrapper(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 32)
    binary.chmod(0o755)
    (target / "libc.so.6").write_bytes(b"fake libc")

    workspace = tmp_path / "workspace"
    result = init_challenge(target, workspace)

    init_json = workspace / "findings" / "init.json"
    run_wrapper = workspace / "scripts" / "run_chall.sh"

    assert result["binaries"][0]["path"].endswith("target/chall")
    assert result["libc_candidates"][0].endswith("target/libc.so.6")
    assert init_json.exists()
    assert run_wrapper.exists()
    assert os.access(run_wrapper, os.X_OK)

    saved = json.loads(init_json.read_text())
    assert saved["workspace"] == str(workspace)
    assert saved["run_wrappers"][0]["path"] == str(run_wrapper)


def test_init_writes_run_profiles_connection_profiles_events_and_summary(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 32)
    binary.chmod(0o755)

    workspace = tmp_path / "workspace"
    init_challenge(target, workspace)

    assert (workspace / "findings" / "run_profiles.json").exists()
    assert (workspace / "findings" / "connection_profiles.json").exists()
    assert (workspace / "scripts" / "run_target.sh").exists()
    assert (workspace / "findings" / "events.jsonl").exists()
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())
    assert summary["run_profiles"]["default"] == "raw"
    assert summary["target"]["path"] == str(target.resolve())
