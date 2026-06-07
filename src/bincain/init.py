from __future__ import annotations

import json
import os
import platform
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, Callable

from bincain.artifacts import append_event, create_summary_snapshot, update_summary
from bincain.run_profiles import build_connection_profiles, build_run_profiles, write_run_target_wrapper

CommandRunner = Callable[[list[str]], tuple[int, str, str]]
ToolLookup = Callable[[str], str | None]


def init_challenge(
    target: Path | str,
    workspace: Path | str,
    *,
    remote: str | None = None,
    command_runner: CommandRunner | None = None,
    tool_lookup: ToolLookup | None = None,
) -> dict[str, Any]:
    target_path = Path(target).resolve()
    workspace_path = Path(workspace).resolve()
    findings_dir = workspace_path / "findings"
    scripts_dir = workspace_path / "scripts"
    normalized_target_dir = workspace_path / "target"
    _ensure_workspace(workspace_path)

    runner = command_runner or _run_command
    binaries = [_binary_metadata(path) for path in _find_binaries(target_path)]
    target_measurements = _measure_target(target_path, binaries)
    libc_paths = _find_named(target_path, "libc.so")
    ld_paths = _find_loaders(target_path)
    ld_candidates = [str(path) for path in ld_paths]
    sysroot = _detect_sysroot(ld_candidates)
    patching = _patch_binaries(
        binaries=binaries,
        libc_paths=libc_paths,
        ld_paths=ld_paths,
        output_dir=normalized_target_dir,
        command_runner=runner,
        tool_lookup=tool_lookup or shutil.which,
    )
    runnable_binaries = _binaries_with_run_paths(binaries, patching)
    run_wrappers = [_write_run_wrapper(scripts_dir, item, sysroot=sysroot) for item in runnable_binaries]
    primary_binary = runnable_binaries[0] if runnable_binaries else None
    primary_binary_path = Path(primary_binary.get("run_path", primary_binary["path"])) if primary_binary else None
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
    runtime_probe = _runtime_probe(primary_binary_path, runner)
    target_measurements["analysis_posture"] = _analysis_posture(target_measurements, runtime_probe)

    result: dict[str, Any] = {
        "target": str(target_path),
        "workspace": str(workspace_path),
        "binaries": binaries,
        "target_measurements": target_measurements,
        "runtime_probe": runtime_probe,
        "libc_candidates": [str(path) for path in libc_paths],
        "ld_candidates": ld_candidates,
        "run_wrappers": run_wrappers,
        "run_profiles": str(run_profiles_path),
        "connection_profiles": str(connection_profiles_path),
        "run_target": str(run_target),
        "remote": remote,
        "patching": patching,
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
        target={
            "path": str(target_path),
            "binaries": binaries,
            "measurements": target_measurements,
            "runtime_probe": runtime_probe,
        },
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
        "size": path.stat().st_size,
        "entry": _entry_summary(path),
        **elf,
    }


def _find_named(target: Path, prefix: str) -> list[Path]:
    root = target.parent if target.is_file() else target
    return sorted(path for path in root.rglob("*") if path.is_file() and path.name.startswith(prefix))


def _find_loaders(target: Path) -> list[Path]:
    root = target.parent if target.is_file() else target
    names = ("ld-", "ld-linux", "ld.so")
    return sorted(path for path in root.rglob("*") if path.is_file() and path.name.startswith(names))


def _write_run_wrapper(scripts_dir: Path, binary_info: dict[str, Any], *, sysroot: str | None = None) -> dict[str, str]:
    binary = Path(str(binary_info.get("run_path", binary_info["path"])))
    wrapper = scripts_dir / f"run_{_safe_name(binary.name)}.sh"
    command = _wrapper_command(
        binary,
        arch=str(binary_info.get("arch", "unknown")),
        native=bool(binary_info.get("native", True)),
        sysroot=sysroot,
    )
    script = "#!/usr/bin/env bash\nset -euo pipefail\nexec " + command + ' "$@"\n'
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    return {"binary": str(binary), "path": str(wrapper), "command": command}


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)


def _measure_target(target: Path, binaries: list[dict[str, Any]]) -> dict[str, Any]:
    size_total = sum(Path(item["path"]).stat().st_size for item in binaries)
    entry_summaries = [item.get("entry") for item in binaries if item.get("entry")]
    return {
        "path": str(target),
        "size_total": size_total,
        "binary_count": len(binaries),
        "entry_summaries": entry_summaries,
    }


def _runtime_probe(binary: Path | None, command_runner: CommandRunner) -> dict[str, Any]:
    if binary is None:
        return {"status": "not_attempted", "reason": "no binary candidate"}
    returncode, stdout, stderr = command_runner(["timeout", "2", str(binary)])
    status = "completed" if returncode == 0 else "failed"
    if returncode == 124:
        status = "timed_out"
    return {
        "binary": str(binary),
        "command": ["timeout", "2", str(binary)],
        "status": status,
        "returncode": returncode,
        "stdout_preview": _preview(stdout),
        "stderr_preview": _preview(stderr),
    }


def _analysis_posture(measurements: dict[str, Any], runtime_probe: dict[str, Any]) -> dict[str, str]:
    size_total = int(measurements.get("size_total") or 0)
    binary_count = int(measurements.get("binary_count") or 0)
    if size_total <= 256 * 1024 and binary_count <= 2:
        return {
            "name": "static-first",
            "reason": "small target; inspect entry path first and use the probe output as a quick behavior check",
        }
    if runtime_probe.get("status") in {"completed", "timed_out"} and size_total <= 2 * 1024 * 1024:
        return {
            "name": "hybrid-first",
            "reason": "medium target with runnable behavior; alternate entry inspection with targeted runtime checks",
        }
    return {
        "name": "fuzz-first",
        "reason": "large or unclear target; collect behavioral evidence before local reverse engineering",
    }


def _preview(text: str, limit: int = 4096) -> str:
    return text[:limit]


def _empty_run_profiles() -> dict[str, Any]:
    return {"schema": "bincain.run_profiles.v1", "arch": "unknown", "native": True, "default": None, "profiles": {}}


def _entry_summary(path: Path) -> str:
    file_tool = shutil.which("file")
    if file_tool is None:
        return "unknown entry"
    completed = subprocess.run(
        [file_tool, "-b", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    summary = completed.stdout.strip() or completed.stderr.strip()
    return summary or "unknown entry"


def _patch_binaries(
    *,
    binaries: list[dict[str, Any]],
    libc_paths: list[Path],
    ld_paths: list[Path],
    output_dir: Path,
    command_runner: CommandRunner,
    tool_lookup: ToolLookup,
) -> dict[str, Any]:
    pwninit = tool_lookup("pwninit")
    patchelf = tool_lookup("patchelf")
    if not binaries or not libc_paths:
        return _patching_status(False, pwninit, patchelf, "no binary/libc pair available for automatic patching")

    if not patchelf and not pwninit:
        return _patching_status(False, pwninit, patchelf, "patchelf and pwninit are unavailable")

    artifacts = []
    for item in binaries:
        binary = Path(item["path"])
        output = output_dir / f"{binary.name}.patched"
        result = patch_binary_with_loader(
            binary=binary,
            output=output,
            libc=libc_paths[0],
            loader=ld_paths[0] if ld_paths else None,
            command_runner=command_runner,
            prefer_pwninit=bool(pwninit),
        )
        artifacts.append(result)
        if result["status"] == "patched":
            item["patched_path"] = result["output"]

    status = "patched" if any(item["status"] == "patched" for item in artifacts) else "failed"
    return {
        "attempted": True,
        "status": status,
        "pwninit": pwninit,
        "patchelf": patchelf,
        "artifacts": artifacts,
    }


def _patching_status(attempted: bool, pwninit: str | None, patchelf: str | None, reason: str) -> dict[str, Any]:
    return {
        "attempted": attempted,
        "status": "not_attempted",
        "pwninit": pwninit,
        "patchelf": patchelf,
        "reason": reason,
        "artifacts": [],
    }


def patch_binary_with_loader(
    *,
    binary: Path,
    output: Path,
    libc: Path,
    loader: Path | None,
    command_runner: CommandRunner,
    prefer_pwninit: bool = False,
) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, output)
    output.chmod(binary.stat().st_mode | 0o111)

    pwninit_command = ["pwninit", "--bin", str(output), "--libc", str(libc)]
    if loader is not None:
        pwninit_command.extend(["--ld", str(loader)])

    if prefer_pwninit:
        returncode, stdout, stderr = command_runner(pwninit_command)
        if returncode == 0:
            return {
                "binary": str(binary),
                "output": str(output),
                "libc": str(libc),
                "loader": str(loader) if loader else None,
                "status": "patched",
                "tool": "pwninit",
                "pwninit_command": " ".join(pwninit_command),
                "stdout": stdout,
                "stderr": stderr,
            }

    patchelf_command = ["patchelf", "--set-rpath", str(libc.parent)]
    if loader is not None:
        patchelf_command.extend(["--set-interpreter", str(loader)])
    patchelf_command.append(str(output))
    returncode, stdout, stderr = command_runner(patchelf_command)
    status = "patched" if returncode == 0 else "failed"
    return {
        "binary": str(binary),
        "output": str(output),
        "libc": str(libc),
        "loader": str(loader) if loader else None,
        "status": status,
        "tool": "patchelf",
        "pwninit_command": " ".join(pwninit_command),
        "patchelf_command": " ".join(patchelf_command),
        "stdout": stdout,
        "stderr": stderr,
    }


def _binaries_with_run_paths(binaries: list[dict[str, Any]], patching: dict[str, Any]) -> list[dict[str, Any]]:
    patched_by_binary = {
        item["binary"]: item["output"]
        for item in patching.get("artifacts", [])
        if item.get("status") == "patched"
    }
    result = []
    for item in binaries:
        copy = dict(item)
        if item["path"] in patched_by_binary:
            copy["run_path"] = patched_by_binary[item["path"]]
        result.append(copy)
    return result


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


def _run_command(command: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return completed.returncode, completed.stdout, completed.stderr
