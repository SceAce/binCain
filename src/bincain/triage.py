from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from bincain.artifacts import append_event, update_summary
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

CommandRunner = Callable[..., tuple[int, str, str]]


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
    workspace: Path | str | None = None,
    crash_id: str | None = None,
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
    report["id"] = crash_id or output_path.stem
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if workspace is not None:
        _record_crash_summary(Path(workspace), report, output_path)
    return report


def run_gdb_triage(
    *,
    binary: Path | str,
    crash_input: Path | str,
    output: Path | str,
    workspace: Path | str | None = None,
    arch: str = "unknown",
    gdb: str | None = None,
    timeout: int = 10,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    binary_path = Path(binary)
    crash_path = Path(crash_input)
    output_path = Path(output)
    workspace_path = Path(workspace) if workspace is not None else output_path.parent.parent
    output_path.parent.mkdir(parents=True, exist_ok=True)

    script_path = output_path.with_suffix(".gdb")
    log_path = output_path.with_name(output_path.stem + "_gdb.txt")
    script_path.write_text(generate_gdb_script(binary=str(binary_path), crash_input=crash_path))

    debugger = gdb or _default_gdb(arch)
    command = [debugger, "-q", str(binary_path), "-x", str(script_path)]
    runner = command_runner or _run_command
    try:
        returncode, stdout, stderr = runner(command, timeout)
    except TypeError:
        returncode, stdout, stderr = runner(command)
    except subprocess.TimeoutExpired as exc:
        returncode = -1
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        stderr += f"\nGDB timed out after {timeout}s"
    log_path.write_text(stdout + stderr)

    log = stdout + stderr
    if returncode == 0 and _parse_signal(log):
        report = build_crash_report(
            binary=str(binary_path),
            crash_input=crash_path,
            arch=arch,
            signal=_parse_signal(log),
            registers=_parse_registers(log),
            backtrace=_parse_backtrace(log),
        )
        report["status"] = "triaged"
    else:
        report = {
            "schema": "bincain.crash.v1",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "failed",
            "failure_reason": _failure_reason(returncode, log),
            "binary": str(binary_path),
            "arch": arch,
            "signal": _parse_signal(log),
            "crash_input": str(crash_path),
            "input_size": len(crash_path.read_bytes()),
            "registers": {},
            "backtrace": [],
            "controlled_registers": [],
        }
    report.update(
        {
            "id": output_path.stem,
            "gdb": debugger,
            "gdb_command": " ".join(command),
            "gdb_returncode": returncode,
            "gdb_script": str(script_path),
            "gdb_log": str(log_path),
        }
    )
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    _record_gdb_summary(workspace_path, report, output_path)
    return report


def generate_gdb_script(*, binary: str, crash_input: Path | str) -> str:
    return "\n".join(
        [
            "set pagination off",
            "set confirm off",
            "set disassembly-flavor intel",
            f"run < {Path(crash_input)}",
            "info registers",
            "backtrace",
            "info proc mappings",
            "x/16i $pc",
            "x/32gx $sp",
            "quit",
            "",
        ]
    )


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


def _default_gdb(arch: str) -> str:
    return "gdb" if arch.lower() in {"amd64", "x86_64", "i386", "x86", "unknown"} else "gdb-multiarch"


def _parse_signal(log: str) -> str | None:
    match = re.search(r"Program received signal\s+(SIG[A-Z0-9]+)", log)
    return match.group(1) if match else None


def _parse_registers(log: str) -> dict[str, str]:
    registers = {}
    for line in log.splitlines():
        match = re.match(r"\s*([a-zA-Z][a-zA-Z0-9]*)\s+(0x[0-9a-fA-F]+)", line)
        if match:
            registers[match.group(1).lower()] = match.group(2).lower()
    return registers


def _parse_backtrace(log: str) -> list[str]:
    return [line.strip() for line in log.splitlines() if line.lstrip().startswith("#")]


def _failure_reason(returncode: int, log: str) -> str:
    if returncode == -1:
        return "gdb timed out"
    if "No such file" in log:
        return "gdb could not find a required file"
    if "Program received signal" not in log:
        return "gdb did not report a reproducible crash"
    return "gdb triage failed"


def _record_crash_summary(workspace: Path, report: dict[str, Any], output: Path) -> None:
    controlled = report.get("controlled_registers", [])
    if controlled:
        first = controlled[0]
        summary_text = (
            f"{report['id']} reaches {report.get('signal') or 'unknown signal'} in {report['binary']}; "
            f"{first['register']}={first['value']} at cyclic offset {first['offset']}."
        )
    else:
        summary_text = f"{report['id']} triaged for {report['binary']} with {report.get('signal') or 'unknown signal'}."
    append_event(
        workspace,
        source="binCain-triage",
        kind="crash_triaged",
        summary=summary_text,
        artifact=_workspace_relative(workspace, output),
        related=[_workspace_relative(workspace, Path(report["crash_input"]))],
    )
    update_summary(
        workspace,
        selected_crashes=[
            {
                "id": report["id"],
                "summary": summary_text,
                "artifact": _workspace_relative(workspace, output),
                "confidence": "high" if controlled else "medium",
            }
        ],
    )


def _record_gdb_summary(workspace: Path, report: dict[str, Any], output: Path) -> None:
    if report.get("status") == "triaged":
        _record_crash_summary(workspace, report, output)
        return
    summary_text = f"{report['id']} failed GDB triage for {report['binary']}: {report.get('failure_reason', 'unknown failure')}."
    append_event(
        workspace,
        source="binCain-triage",
        kind="crash_triage_failed",
        summary=summary_text,
        artifact=_workspace_relative(workspace, output),
        related=[_workspace_relative(workspace, Path(report["crash_input"]))],
    )
    update_summary(
        workspace,
        negative_results=[
            {
                "topic": "gdb triage",
                "count": 1,
                "latest_fact": None,
                "summary": summary_text,
                "artifact": _workspace_relative(workspace, output),
            }
        ],
    )


def _workspace_relative(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _run_command(command: list[str], timeout: int) -> tuple[int, str, str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    return completed.returncode, completed.stdout, completed.stderr
