import json
from pathlib import Path

from bincain.cyclic import cyclic
from bincain.triage import build_crash_report, generate_gdb_script, run_gdb_triage, write_crash_report


def test_build_crash_report_detects_cyclic_register_offsets(tmp_path: Path):
    crash_input = tmp_path / "crash.bin"
    crash_input.write_bytes(cyclic(128))

    report = build_crash_report(
        binary="target/chall",
        crash_input=crash_input,
        arch="amd64",
        signal="SIGSEGV",
        registers={"rip": "0x6161616b", "rsp": "0x7fffffffd000"},
        backtrace=["main+42"],
    )

    assert report["binary"] == "target/chall"
    assert report["controlled_registers"][0]["register"] == "rip"
    assert report["controlled_registers"][0]["offset"] == 40


def test_write_crash_report_writes_json(tmp_path: Path):
    crash_input = tmp_path / "crash.bin"
    crash_input.write_bytes(cyclic(64))
    output = tmp_path / "report.json"

    write_crash_report(
        output=output,
        binary="target/chall",
        crash_input=crash_input,
        arch="i386",
        signal="SIGSEGV",
        registers={"eip": "0x61616166"},
        backtrace=[],
    )

    saved = json.loads(output.read_text())
    assert saved["arch"] == "i386"
    assert saved["controlled_registers"][0]["register"] == "eip"


def test_generate_gdb_script_captures_core_debugger_evidence(tmp_path: Path):
    crash_input = tmp_path / "crash.bin"
    crash_input.write_bytes(b"AAAA")

    script = generate_gdb_script(binary="target/chall", crash_input=crash_input)

    assert "set pagination off" in script
    assert f"run < {crash_input}" in script
    assert "info registers" in script
    assert "backtrace" in script
    assert "info proc mappings" in script
    assert "x/16i $pc" in script


def test_run_gdb_triage_writes_script_log_and_report(tmp_path: Path):
    binary = tmp_path / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    crash_input = tmp_path / "crash.bin"
    crash_input.write_bytes(cyclic(128))

    def fake_runner(command):
        assert command[0] == "gdb"
        assert "-x" in command
        return (
            0,
            "Program received signal SIGSEGV\nrip            0x6161616b\nrsp            0x7fffffffd000\n#0  main\n",
            "",
        )

    report = run_gdb_triage(
        binary=binary,
        crash_input=crash_input,
        output=tmp_path / "findings" / "crash_000001.json",
        arch="amd64",
        command_runner=fake_runner,
    )

    assert report["signal"] == "SIGSEGV"
    assert report["registers"]["rip"] == "0x6161616b"
    assert report["controlled_registers"][0]["offset"] == 40
    assert Path(report["gdb_script"]).exists()
    assert Path(report["gdb_log"]).exists()
