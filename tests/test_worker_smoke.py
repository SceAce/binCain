import json
from pathlib import Path

from bincain.cyclic import cyclic
from bincain.init import init_challenge
from bincain.report import write_exploit_chain_report
from bincain.triage import write_crash_report


def test_worker_smoke_generates_exploit_chain_report(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 64)
    binary.chmod(0o755)

    workspace = tmp_path / "workspace"
    init_result = init_challenge(target, workspace)

    crash_input = workspace / "crashes" / "crash.bin"
    crash_input.parent.mkdir(parents=True, exist_ok=True)
    crash_input.write_bytes(cyclic(128))
    crash_report = workspace / "findings" / "crash_000001.json"
    write_crash_report(
        output=crash_report,
        binary=init_result["binaries"][0]["path"],
        crash_input=crash_input,
        arch="amd64",
        signal="SIGSEGV",
        registers={"rip": "0x6161616b"},
    )

    proof_report = workspace / "findings" / "proof_crash_000001_pc.json"
    proof_report.write_text(
        json.dumps(
            {
                "id": "proof_crash_000001_pc",
                "level": 3,
                "claim": "controllable instruction pointer",
                "status": "verified",
            }
        )
    )

    report_text = write_exploit_chain_report(
        crash_report=crash_report,
        proof_report=proof_report,
        workspace=workspace,
    )

    reports = sorted((workspace / "findings").glob("exploit_chain_summary_*.md"))
    assert len(reports) == 1
    assert "漏洞点" in report_text
    assert "攻击链" in report_text
    assert "verified" in report_text
