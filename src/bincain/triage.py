from __future__ import annotations

import json
import re
import subprocess
import time
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

CommandRunner = Callable[[list[str], int], tuple[int, str, str]]


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
        "status": "triaged",
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
    workspace: Path | str,
    arch: str = "unknown",
    gdb: str | None = None,
    profile: str | None = None,
    timeout: int = 10,
    command_runner: CommandRunner | None = None,
    launch_inferior: bool = True,
    startup_delay: float = 0.1,
) -> dict[str, Any]:
    binary_path = Path(binary)
    crash_path = Path(crash_input)
    output_path = Path(output)
    workspace_path = Path(workspace)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    script_path = output_path.with_suffix(".gdb")
    log_path = output_path.with_name(output_path.stem + "_gdb.txt")
    debug_plan = resolve_debug_plan(workspace=workspace_path, binary=binary_path, arch=arch, profile=profile, gdb=gdb)
    script_path.write_text(generate_gdb_script(crash_path, plan=debug_plan))

    command = build_gdb_command(debug_plan, script_path)
    debugger = str(debug_plan["gdb"])
    runner = command_runner or _run_command
    inferior_result = {"command": None, "returncode": None, "stdout": "", "stderr": "", "started": False}
    inferior = None
    try:
        if launch_inferior and debug_plan.get("mode") == "remote":
            inferior, inferior_result["command"] = _launch_inferior(debug_plan, crash_path)
            inferior_result["started"] = True
            if startup_delay > 0:
                time.sleep(startup_delay)
        returncode, stdout, stderr = runner(command, timeout)
        if inferior is not None:
            inferior_result["returncode"], inferior_result["stdout"], inferior_result["stderr"] = _finish_inferior(inferior, timeout)
    except subprocess.TimeoutExpired as exc:
        returncode = -1
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        stderr += f"\nGDB timed out after {timeout}s"
        if inferior is not None:
            inferior_result["returncode"], inferior_result["stdout"], inferior_result["stderr"] = _finish_inferior(inferior, 1)
    except OSError as exc:
        returncode = 1
        stdout = ""
        stderr = str(exc)
    log_path.write_text(stdout + stderr)
    if inferior_result["command"] or inferior_result["stdout"] or inferior_result["stderr"]:
        with log_path.open("a", encoding="utf-8") as handle:
            if inferior_result["command"]:
                handle.write("\n[inferior-command]\n" + str(inferior_result["command"]) + "\n")
            if inferior_result["stdout"]:
                handle.write("\n[inferior-stdout]\n" + str(inferior_result["stdout"]))
            if inferior_result["stderr"]:
                handle.write("\n[inferior-stderr]\n" + str(inferior_result["stderr"]))

    if returncode == 0 and _parse_signal(stdout + stderr):
        report = build_crash_report(
            binary=str(binary_path),
            crash_input=crash_path,
            arch=arch,
            signal=_parse_signal(stdout + stderr),
            registers=_parse_registers(stdout + stderr),
            backtrace=_parse_backtrace(stdout + stderr),
        )
        report["status"] = "triaged"
    else:
        report = {
            "schema": "bincain.crash.v1",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "failed",
            "failure_reason": _failure_reason(returncode, stdout + stderr),
            "binary": str(binary_path),
            "arch": arch,
            "crash_input": str(crash_path),
            "input_size": len(crash_path.read_bytes()),
            "registers": {},
            "backtrace": [],
            "controlled_registers": [],
            "signal": _parse_signal(stdout + stderr),
        }
    report["id"] = output_path.stem
    report["gdb"] = debugger
    report["gdb_command"] = " ".join(command)
    report["attempted_command"] = report["gdb_command"]
    report["gdb_script"] = str(script_path)
    report["gdb_log"] = str(log_path)
    report["gdb_returncode"] = returncode
    report["debug_profile"] = debug_plan["profile"]
    report["debug_plan"] = {
        "gdb": debug_plan["gdb"],
        "argv": debug_plan["argv"],
        "mode": debug_plan["mode"],
        "target_remote": debug_plan.get("target_remote"),
        "run_argv": debug_plan.get("run_argv"),
    }
    if inferior_result["command"] is not None:
        report["inferior_command"] = " ".join(str(item) for item in inferior_result["command"])
        report["inferior_returncode"] = inferior_result["returncode"]
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    _record_gdb_summary(workspace_path, report, output_path)
    return report


def generate_gdb_script(crash_input: Path | str, *, plan: dict[str, Any] | None = None) -> str:
    crash_path = Path(crash_input)
    lines = [
        "set pagination off",
        "set confirm off",
        "set disassembly-flavor intel",
    ]
    if plan is not None and plan.get("arch_command"):
        lines.append(str(plan["arch_command"]))
    if plan is not None and plan.get("mode") == "remote":
        target_remote = str(plan["target_remote"])
        run_argv = [str(arg) for arg in plan.get("run_argv", [])]
        sysroot = plan.get("sysroot")
        if run_argv:
            lines.append("file " + json.dumps(run_argv[-1]))
            lines.append("set remote exec-file " + json.dumps(run_argv[-1]))
        if sysroot:
            lines.append("set sysroot " + json.dumps(str(sysroot)))
        lines.append(f"target remote {target_remote}")
        lines.append("continue")
    else:
        lines.append(f"run < {crash_path}")
    lines.extend(
        [
            "info registers",
            "backtrace",
            "info proc mappings",
            "x/16i $pc",
            "x/32gx $sp",
            "quit",
            "",
        ]
    )
    return "\n".join(lines)


def resolve_debug_plan(
    *,
    workspace: Path,
    binary: Path,
    arch: str,
    profile: str | None,
    gdb: str | None,
) -> dict[str, Any]:
    document = _load_run_profile_document(workspace)
    profiles = _profiles_map(document)
    selected_profile = profile or _default_debug_profile(document)
    entry = profiles.get(selected_profile)
    if entry is None:
        debugger = gdb or _default_gdb(arch)
        return {
            "profile": selected_profile,
            "gdb": debugger,
            "argv": [str(binary)],
            "mode": "native",
            "run_argv": [str(binary)],
            "arch_command": _gdb_arch_command(arch),
        }

    argv = [str(item) for item in entry.get("argv", [])]
    debugger = gdb or _default_gdb(arch, selected_profile)
    plan: dict[str, Any] = {
        "profile": selected_profile,
        "gdb": debugger,
        "argv": argv,
        "run_argv": argv,
        "mode": "native",
        "arch_command": _gdb_arch_command(arch),
        "sysroot": _extract_sysroot(argv),
    }
    if selected_profile in {"qemu", "qemu-debug"} and argv and Path(argv[0]).name.startswith("qemu-"):
        run_argv = list(argv)
        port = "1234"
        if len(run_argv) >= 3 and run_argv[1] == "-g":
            port = run_argv[2]
        else:
            run_argv = [run_argv[0], "-g", port, *run_argv[1:]]
        plan["mode"] = "remote"
        plan["target_remote"] = ":" + port
        plan["run_argv"] = run_argv
    return plan


def build_gdb_command(plan: dict[str, Any], script_path: Path) -> list[str]:
    debugger = str(plan["gdb"])
    if plan.get("mode") == "remote":
        return [debugger, "-q", "-x", str(script_path)]
    target_binary = str(plan["run_argv"][-1]) if plan.get("run_argv") else ""
    return [debugger, "-q", target_binary, "-x", str(script_path)]


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


def _default_gdb(arch: str, profile: str | None = None) -> str:
    if profile == "qemu-debug":
        return "gdb-multiarch"
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


def _run_command(command: list[str], timeout: int) -> tuple[int, str, str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    return completed.returncode, completed.stdout, completed.stderr


def _load_run_profile_document(workspace: Path) -> dict[str, Any]:
    run_profiles_path = workspace / "findings" / "run_profiles.json"
    if not run_profiles_path.exists():
        return {}
    data = json.loads(run_profiles_path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _profiles_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = document.get("profiles", {})
    return profiles if isinstance(profiles, dict) else {}


def _default_debug_profile(document: dict[str, Any]) -> str:
    profiles = _profiles_map(document)
    default_profile = document.get("default")
    if default_profile == "qemu" and "qemu-debug" in profiles:
        return "qemu-debug"
    if default_profile == "qemu" and "qemu" in profiles:
        return "qemu"
    if default_profile == "debug" and "debug" in profiles:
        return "debug"
    if "debug" in profiles:
        return "debug"
    if "qemu-debug" in profiles:
        return "qemu-debug"
    if "qemu" in profiles:
        return "qemu"
    return "debug"


def _gdb_arch_command(arch: str) -> str | None:
    value = arch.lower()
    mapping = {
        "arm": "set architecture arm",
        "aarch64": "set architecture aarch64",
        "mips": "set architecture mips:isa32",
        "mipsel": "set architecture mips:isa32",
    }
    return mapping.get(value)


def _extract_sysroot(argv: list[str]) -> str | None:
    for index, item in enumerate(argv):
        if item == "-L" and index + 1 < len(argv):
            return argv[index + 1]
    return None


def _launch_inferior(plan: dict[str, Any], crash_input: Path) -> tuple[subprocess.Popen[bytes], list[str]]:
    command = [str(item) for item in plan.get("run_argv", [])]
    stdin_handle = crash_input.open("rb")
    try:
        process = subprocess.Popen(command, stdin=stdin_handle, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        stdin_handle.close()
        raise
    process._bincain_stdin = stdin_handle  # type: ignore[attr-defined]
    return process, command


def _finish_inferior(process: subprocess.Popen[bytes], timeout: int) -> tuple[int | None, str, str]:
    try:
        stdout, stderr = process.communicate(timeout=max(timeout, 1))
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
    finally:
        stdin_handle = getattr(process, "_bincain_stdin", None)
        if stdin_handle is not None:
            stdin_handle.close()
    return process.returncode, _decode_output(stdout), _decode_output(stderr)


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


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
