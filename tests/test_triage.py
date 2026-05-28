import json
from pathlib import Path

from bincain.cyclic import cyclic
from bincain.triage import build_crash_report, write_crash_report


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
