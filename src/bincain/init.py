from __future__ import annotations

import json
import os
import platform
import shutil
import struct
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, create_summary_snapshot, update_summary
from bincain.run_profiles import build_connection_profiles, build_run_profiles, write_run_target_wrapper


def init_challenge(target: Path | str, workspace: Path | str, remote: str | None = None) -> dict[str, Any]:
    target_path = Path(target).resolve()
    workspace_path = Path(workspace).resolve()
    findings_dir = workspace_path / "findings"
    scripts_dir = workspace_path / "scripts"
    _ensure_workspace(workspace_path)

    binaries = [_binary_metadata(path) for path in _find_binaries(target_path)]
    libc_candidates = [str(path) for path in _find_named(target_path, "libc.so")]
    ld_candidates = [str(path) for path in _find_named(target_path, "ld-")]
    sysroot = _detect_sysroot(ld_candidates)
    run_wrappers = [_write_run_wrapper(scripts_dir, item, sysroot=sysroot) for item in binaries]
    primary_binary = binaries[0] if binaries else None
    primary_binary_path = Path(primary_binary["path"]) if primary_binary else None
    run_profiles = (
        build_run_profiles(
            primary_binary_path,
            arch=str(primary_binary.get("arch", "unknown")),
            native=bool(primary_binary.get("native", True)),
            sysroot=sysroot,
        )
        if primary_binary_path
        else _empty_run_profiles()
    )
    connection_profiles = build_connection_profiles(remote=remote)
    run_profiles_path = findings_dir / "run_profiles.json"
    connection_profiles_path = findings_dir / "connection_profiles.json"
    run_profiles_path.write_text(json.dumps(run_profiles, indent=2, sort_keys=True) + "\n")
    connection_profiles_path.write_text(json.dumps(connection_profiles, indent=2, sort_keys=True) + "\n")
    run_target = write_run_target_wrapper(scripts_dir, run_profiles_path)

    result: dict[str, Any] = {
        "target": str(target_path),
        "workspace": str(workspace_path),
        "binaries": binaries,
        "libc_candidates": libc_candidates,
        "ld_candidates": ld_candidates,
        "run_wrappers": run_wrappers,
        "run_profiles": str(run_profiles_path),
        "connection_profiles": str(connection_profiles_path),
        "run_target": str(run_target),
        "remote": remote,
        "patching": _patching_status(),
    }
    (findings_dir / "init.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    event = append_event(
        workspace_path,
        source="binCain-init",
        kind="initialized",
        summary=f"Initialized {len(binaries)} binary candidate(s) from {target_path}",
        artifact="findings/init.json",
    )
    summary = update_summary(
        workspace_path,
        target={"path": str(target_path), "binaries": binaries},
        run_profiles=run_profiles,
        connection_profiles=connection_profiles,
    )
    result["event"] = event
    result["summary"] = str(create_summary_snapshot(workspace_path, summary))
    return result


def _ensure_workspace(workspace: Path) -> None:
    for name in ("target", "scripts", "fuzz", "crashes", "findings", "notes", "proofs"):
        (workspace / name).mkdir(parents=True, exist_ok=True)


def _find_binaries(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if _looks_like_elf(target) else []
    candidates = [path for path in target.rglob("*") if path.is_file() and _looks_like_elf(path)]
    return sorted(candidates)


def _looks_like_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def _binary_metadata(path: Path) -> dict[str, Any]:
    elf = _elf_metadata(path)
    return {
        "path": str(path),
        "name": path.name,
        "mode": oct(path.stat().st_mode & 0o777),
        "executable": os.access(path, os.X_OK),
        **elf,
    }


def _find_named(target: Path, prefix: str) -> list[Path]:
    root = target.parent if target.is_file() else target
    return sorted(path for path in root.rglob("*") if path.is_file() and path.name.startswith(prefix))


def _write_run_wrapper(scripts_dir: Path, binary_info: dict[str, Any], *, sysroot: str | None = None) -> dict[str, str]:
    binary = Path(str(binary_info["path"]))
    wrapper = scripts_dir / f"run_{_safe_name(binary.name)}.sh"
    command = _wrapper_command(binary, arch=str(binary_info.get("arch", "unknown")), native=bool(binary_info.get("native", True)), sysroot=sysroot)
    script = "#!/usr/bin/env bash\nset -euo pipefail\nexec " + command + ' "$@"\n'
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    return {"binary": str(binary), "path": str(wrapper), "command": command}


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)


def _empty_run_profiles() -> dict[str, Any]:
    return {"schema": "bincain.run_profiles.v1", "arch": "unknown", "native": True, "default": None, "profiles": {}}


def _patching_status() -> dict[str, Any]:
    pwninit = shutil.which("pwninit")
    patchelf = shutil.which("patchelf")
    return {
        "attempted": False,
        "pwninit": pwninit,
        "patchelf": patchelf,
        "reason": "automatic patching is not enabled in the V1 scaffold",
    }


def _elf_metadata(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()[:64]
    except OSError:
        return {"arch": "unknown", "bits": None, "endian": "unknown", "native": True}
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return {"arch": "unknown", "bits": None, "endian": "unknown", "native": True}

    elf_class = data[4]
    elf_data = data[5]
    machine = struct.unpack("<H" if elf_data == 1 else ">H", data[18:20])[0]
    arch = _machine_to_arch(machine, elf_data)
    bits = 64 if elf_class == 2 else 32 if elf_class == 1 else None
    endian = {1: "little", 2: "big"}.get(elf_data, "unknown")
    native = _host_supports_arch(arch)
    return {
        "arch": arch,
        "bits": bits,
        "endian": endian,
        "native": native,
    }


def _machine_to_arch(machine: int, elf_data: int) -> str:
    if machine == 0x03:
        return "i386"
    if machine == 0x3E:
        return "amd64"
    if machine == 0x28:
        return "arm"
    if machine == 0xB7:
        return "aarch64"
    if machine == 0x08:
        return "mipsel" if elf_data == 1 else "mips"
    return "unknown"


def _detect_sysroot(ld_candidates: list[str]) -> str | None:
    if not ld_candidates:
        return None
    try:
        return str(Path(ld_candidates[0]).resolve().parent)
    except OSError:
        return None


def _host_supports_arch(arch: str) -> bool:
    host = platform.machine().lower()
    compatibility = {
        "x86_64": {"amd64", "x86_64", "i386", "x86"},
        "amd64": {"amd64", "x86_64", "i386", "x86"},
        "i386": {"i386", "x86"},
        "i686": {"i386", "x86"},
        "aarch64": {"aarch64", "arm"},
        "arm64": {"aarch64", "arm"},
        "armv7l": {"arm"},
        "armv6l": {"arm"},
        "mips": {"mips"},
        "mipsel": {"mipsel"},
    }
    if arch == "unknown":
        return True
    supported = compatibility.get(host, {host})
    return arch in supported


def _wrapper_command(binary: Path, *, arch: str, native: bool, sysroot: str | None) -> str:
    if native:
        return json.dumps(str(binary))
    qemu_binary = {
        "arm": "qemu-arm",
        "aarch64": "qemu-aarch64",
        "mips": "qemu-mips",
        "mipsel": "qemu-mipsel",
    }.get(arch.lower())
    if qemu_binary is None:
        return json.dumps(str(binary))
    parts = [json.dumps(qemu_binary)]
    if sysroot is not None:
        parts.extend(["-L", json.dumps(sysroot)])
    parts.append(json.dumps(str(binary)))
    return " ".join(parts)
