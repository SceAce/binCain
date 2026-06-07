import json
import os
from pathlib import Path

from bincain.init import init_challenge, patch_binary_with_loader


def _fake_elf(*, elf_class: int = 2, endian: int = 1, machine: int = 0x3E) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = endian
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little" if endian == 1 else "big")
    header[18:20] = machine.to_bytes(2, "little" if endian == 1 else "big")
    return bytes(header)


def test_init_challenge_writes_metadata_and_run_wrapper(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(_fake_elf())
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
    assert saved["binaries"][0]["arch"] == "amd64"
    assert saved["binaries"][0]["bits"] == 64
    assert saved["binaries"][0]["endian"] == "little"


def test_init_writes_run_profiles_connection_profiles_events_and_summary(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(_fake_elf())
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


def test_init_generates_qemu_profile_and_remote_connection_for_cross_arch_target(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(_fake_elf(elf_class=1, endian=1, machine=0x08))
    binary.chmod(0o755)
    ld = target / "ld-linux-mipsel.so.1"
    ld.write_bytes(b"fake loader")

    workspace = tmp_path / "workspace"
    result = init_challenge(target, workspace, remote="ctf.example:31337")

    run_profiles = json.loads((workspace / "findings" / "run_profiles.json").read_text())
    connection_profiles = json.loads((workspace / "findings" / "connection_profiles.json").read_text())

    assert result["remote"] == "ctf.example:31337"
    assert result["binaries"][0]["arch"] == "mipsel"
    assert run_profiles["profiles"]["qemu"]["argv"][0] == "qemu-mipsel"
    assert run_profiles["profiles"]["qemu"]["argv"][1:3] == ["-L", str(target.resolve())]
    assert connection_profiles["profiles"]["remote"]["host"] == "ctf.example"
    assert connection_profiles["profiles"]["remote"]["port"] == 31337


def test_init_challenge_records_size_entry_summary_runtime_probe_and_analysis_posture(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(_fake_elf() + b"\x00" * 128)
    binary.chmod(0o755)
    commands: list[list[str]] = []

    def runner(command: list[str]) -> tuple[int, str, str]:
        commands.append(command)
        return 0, "menu: 1) add\n", ""

    workspace = tmp_path / "workspace"
    result = init_challenge(target, workspace, command_runner=runner)

    item = result["binaries"][0]
    assert item["size"] == binary.stat().st_size
    assert item["entry"]
    assert result["target_measurements"]["size_total"] == binary.stat().st_size
    assert result["target_measurements"]["binary_count"] == 1
    assert commands == [["timeout", "2", str(binary)]]
    assert result["runtime_probe"]["status"] == "completed"
    assert result["runtime_probe"]["stdout_preview"] == "menu: 1) add\n"
    assert result["target_measurements"]["analysis_posture"]["name"] == "static-first"

    saved = json.loads((workspace / "findings" / "init.json").read_text())
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())
    assert saved["runtime_probe"]["binary"] == str(binary)
    assert summary["target"]["runtime_probe"]["status"] == "completed"


def test_init_challenge_uses_existing_loader_and_libc_for_patched_copy(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(_fake_elf())
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
