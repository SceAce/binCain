from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any


_QEMU_BINARIES = {
    "arm": "qemu-arm",
    "aarch64": "qemu-aarch64",
    "mips": "qemu-mips",
    "mipsel": "qemu-mipsel",
}


def build_run_profiles(
    binary: Path | str,
    *,
    arch: str = "unknown",
    native: bool | None = None,
    sysroot: Path | str | None = None,
) -> dict[str, Any]:
    binary_path = str(Path(binary))
    normalized_arch = arch.lower()
    if native is None:
        native = _host_supports_arch(normalized_arch)

    profiles = {
        "raw": {
            "argv": [binary_path],
            "env": {},
            "stdin": True,
            "notes": "Minimal local execution.",
        },
        "debug": {
            "argv": ["gdb", "-q", "--args", binary_path],
            "env": {},
            "stdin": True,
            "notes": "Debugger-friendly execution.",
        },
        "fuzz": {
            "argv": [binary_path],
            "env": {},
            "stdin": True,
            "notes": "Clean local execution for fuzzing wrappers.",
        },
    }

    qemu_binary = _QEMU_BINARIES.get(normalized_arch)
    if qemu_binary and not native:
        qemu_argv = [qemu_binary]
        qemu_debug_argv = [qemu_binary, "-g", "1234"]
        if sysroot is not None:
            qemu_argv.extend(["-L", str(Path(sysroot))])
            qemu_debug_argv.extend(["-L", str(Path(sysroot))])
        qemu_argv.append(binary_path)
        qemu_debug_argv.append(binary_path)
        profiles["qemu"] = {
            "argv": qemu_argv,
            "env": {},
            "stdin": True,
            "notes": f"User-mode emulation for {normalized_arch}.",
        }
        profiles["qemu-debug"] = {
            "argv": qemu_debug_argv,
            "env": {},
            "stdin": True,
            "notes": f"User-mode emulation with GDB stub for {normalized_arch}.",
        }

    default_profile = "raw" if native or "qemu" not in profiles else "qemu"
    return {
        "schema": "bincain.run_profiles.v1",
        "arch": normalized_arch,
        "native": native,
        "default": default_profile,
        "profiles": profiles,
    }


def build_connection_profiles(*, remote: str | None = None) -> dict[str, Any]:
    profiles: dict[str, Any] = {}
    if remote is not None:
        profiles["remote"] = parse_remote_target(remote)
    return {
        "schema": "bincain.connection_profiles.v1",
        "profiles": profiles,
    }


def write_run_target_wrapper(scripts_dir: Path | str, run_profiles_path: Path | str) -> Path:
    scripts_path = Path(scripts_dir)
    scripts_path.mkdir(parents=True, exist_ok=True)
    profiles_path = Path(run_profiles_path)
    wrapper = scripts_path / "run_target.sh"
    runner = (
        "import json, os, subprocess, sys; "
        "profile=sys.argv[1] or None; profiles_path=sys.argv[2]; extra=sys.argv[3:]; "
        "data=json.load(open(profiles_path, encoding='utf-8')); "
        "profile = data.get('default') if profile in (None, '', 'default') else profile; "
        "profiles=data.get('profiles', {}); "
        "entry=profiles.get(profile); "
        "sys.exit(f'unknown run profile: {profile}') if entry is None else None; "
        "argv=list(entry.get('argv', [])) + extra; "
        "env=os.environ.copy(); env.update(entry.get('env', {})); "
        "raise SystemExit(subprocess.call(argv, env=env))"
    )
    script = f"""#!/usr/bin/env bash
set -euo pipefail

profile=""
if [[ "${{1:-}}" == "--profile" ]]; then
  profile="${{2:-}}"
  shift 2
fi

python3 -c {json.dumps(runner)} "$profile" {json.dumps(str(profiles_path))} "$@"
"""
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    return wrapper


def parse_remote_target(remote: str) -> dict[str, Any]:
    value = remote.strip()
    if not value:
        raise ValueError("remote target must not be empty")
    if value.startswith("["):
        host, separator, port_s = value.partition("]:")
        if separator != "]:":
            raise ValueError(f"remote target must be host:port, got {remote!r}")
        host = host[1:]
    else:
        host, separator, port_s = value.rpartition(":")
        if separator != ":" or not host:
            raise ValueError(f"remote target must be host:port, got {remote!r}")
    try:
        port = int(port_s, 10)
    except ValueError as exc:
        raise ValueError(f"invalid remote port in {remote!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"remote port out of range in {remote!r}")
    return {
        "host": host,
        "port": port,
        "transport": "tcp",
        "source": "user-supplied",
    }


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
