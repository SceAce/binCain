from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, create_summary_snapshot, update_summary
from bincain.run_profiles import build_connection_profiles, build_run_profiles, write_run_target_wrapper


def init_challenge(target: Path | str, workspace: Path | str) -> dict[str, Any]:
    target_path = Path(target).resolve()
    workspace_path = Path(workspace).resolve()
    findings_dir = workspace_path / "findings"
    scripts_dir = workspace_path / "scripts"
    _ensure_workspace(workspace_path)

    binaries = [_binary_metadata(path) for path in _find_binaries(target_path)]
    libc_candidates = [str(path) for path in _find_named(target_path, "libc.so")]
    ld_candidates = [str(path) for path in _find_named(target_path, "ld-")]
    run_wrappers = [_write_run_wrapper(scripts_dir, item["path"]) for item in binaries]
    primary_binary = Path(binaries[0]["path"]) if binaries else None
    run_profiles = build_run_profiles(primary_binary) if primary_binary else _empty_run_profiles()
    connection_profiles = build_connection_profiles()
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
    return {
        "path": str(path),
        "name": path.name,
        "mode": oct(path.stat().st_mode & 0o777),
        "executable": os.access(path, os.X_OK),
    }


def _find_named(target: Path, prefix: str) -> list[Path]:
    root = target.parent if target.is_file() else target
    return sorted(path for path in root.rglob("*") if path.is_file() and path.name.startswith(prefix))


def _write_run_wrapper(scripts_dir: Path, binary_path: str) -> dict[str, str]:
    binary = Path(binary_path)
    wrapper = scripts_dir / f"run_{_safe_name(binary.name)}.sh"
    script = "#!/usr/bin/env bash\nset -euo pipefail\nexec " + json.dumps(str(binary)) + ' "$@"\n'
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    return {"binary": str(binary), "path": str(wrapper), "command": str(wrapper)}


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)


def _empty_run_profiles() -> dict[str, Any]:
    return {"schema": "bincain.run_profiles.v1", "default": None, "profiles": {}}


def _patching_status() -> dict[str, Any]:
    pwninit = shutil.which("pwninit")
    patchelf = shutil.which("patchelf")
    return {
        "attempted": False,
        "pwninit": pwninit,
        "patchelf": patchelf,
        "reason": "automatic patching is not enabled in the V1 scaffold",
    }
