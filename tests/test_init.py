import json
import os
from pathlib import Path

from bincain.init import init_challenge, patch_binary_with_loader


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


def test_init_challenge_records_size_and_entry_summary(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 64)
    binary.chmod(0o755)

    workspace = tmp_path / "workspace"
    result = init_challenge(target, workspace)

    item = result["binaries"][0]
    assert item["size"] == binary.stat().st_size
    assert item["entry"]
    assert result["target_measurements"]["size_total"] == binary.stat().st_size
    assert result["target_measurements"]["binary_count"] == 1


def test_init_challenge_uses_existing_loader_and_libc_for_patched_copy(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 32)
    binary.chmod(0o755)
    libc = target / "libc.so.6"
    libc.write_bytes(b"fake libc")
    loader = target / "ld-linux-x86-64.so.2"
    loader.write_bytes(b"fake loader")

    workspace = tmp_path / "workspace"
    result = init_challenge(
        target,
        workspace,
        command_runner=lambda command: (0, "", ""),
        tool_lookup=lambda name: f"/usr/bin/{name}",
    )

    patched = workspace / "target" / "chall.patched"
    assert patched.exists()
    assert result["patching"]["attempted"] is True
    assert result["patching"]["status"] == "patched"
    assert result["patching"]["artifacts"][0]["output"] == str(patched)
    assert "--libc" in result["patching"]["artifacts"][0]["pwninit_command"]
    wrapper = Path(result["run_wrappers"][0]["path"])
    assert json.dumps(str(patched)) in wrapper.read_text()


def test_patch_binary_with_loader_records_patchelf_failure(tmp_path: Path):
    binary = tmp_path / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    binary.chmod(0o755)
    libc = tmp_path / "libc.so.6"
    libc.write_bytes(b"fake libc")
    loader = tmp_path / "ld-linux.so"
    loader.write_bytes(b"fake loader")

    result = patch_binary_with_loader(
        binary=binary,
        output=tmp_path / "chall.patched",
        libc=libc,
        loader=loader,
        command_runner=lambda command: (1, "", "bad interpreter"),
    )

    assert result["status"] == "failed"
    assert result["tool"] == "patchelf"
    assert "bad interpreter" in result["stderr"]
