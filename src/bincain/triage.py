from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bincain.cyclic import cyclic_find

_CONTROL_REGISTERS = {
    "amd64": ("rip",),
    "x86_64": ("rip",),
    "i386": ("eip",),
    "x86": ("eip",),
    "arm": ("pc", "lr"),
    "aarch64": ("pc", "lr", "x30"),
    "mips": ("pc", "ra"),
    "mipsel": ("pc", "ra"),
}


def build_crash_report(
    *,
    binary: str,
    crash_input: Path | str,
    arch: str = "unknown",
    signal: str | None = None,
    registers: dict[str, str | int] | None = None,
    backtrace: list[str] | None = None,
) -> dict[str, Any]:
    crash_path = Path(crash_input)
    input_bytes = crash_path.read_bytes()
    normalized_registers = _normalize_registers(registers or {})
    return {
        "schema": "bincain.crash.v1",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "binary": binary,
        "arch": arch,
        "signal": signal,
        "crash_input": str(crash_path),
        "input_size": len(input_bytes),
        "registers": normalized_registers,
        "backtrace": backtrace or [],
        "controlled_registers": _controlled_registers(arch, normalized_registers),
        "gdb_command": _gdb_command(binary, crash_path),
    }


def write_crash_report(
    *,
    output: Path | str,
    binary: str,
    crash_input: Path | str,
    arch: str = "unknown",
    signal: str | None = None,
    registers: dict[str, str | int] | None = None,
    backtrace: list[str] | None = None,
) -> dict[str, Any]:
    report = build_crash_report(
        binary=binary,
        crash_input=crash_input,
        arch=arch,
        signal=signal,
        registers=registers,
        backtrace=backtrace,
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def _normalize_registers(registers: dict[str, str | int]) -> dict[str, str]:
    normalized = {}
    for name, value in registers.items():
        key = name.lower()
        if isinstance(value, int):
            normalized[key] = hex(value)
        else:
            normalized[key] = value.lower()
    return normalized


def _controlled_registers(arch: str, registers: dict[str, str]) -> list[dict[str, Any]]:
    preferred = _CONTROL_REGISTERS.get(arch.lower(), ())
    names = list(preferred) + [name for name in registers if name not in preferred]
    findings = []
    for name in names:
        value = registers.get(name)
        if value is None:
            continue
        parsed = _parse_int(value)
        if parsed is None:
            continue
        offset = cyclic_find(parsed, width=4)
        if offset is None:
            offset = cyclic_find(parsed, width=8)
        if offset is None:
            continue
        findings.append({"register": name, "value": value, "offset": offset})
    return findings


def _parse_int(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        return None


def _gdb_command(binary: str, crash_input: Path) -> str:
    return f"gdb -q {json.dumps(binary)} -ex 'run < {crash_input}' -ex 'info registers' -ex 'bt' -ex 'quit'"
