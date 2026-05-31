from pathlib import Path

from bincain.report import build_exploit_chain_report, write_exploit_chain_report


def test_build_exploit_chain_report_contains_chinese_sections(tmp_path: Path):
    crash = tmp_path / "crash.json"
    crash.write_text(
        """
        {
          "id": "crash_000001",
          "binary": "target/chall",
          "signal": "SIGSEGV",
          "controlled_registers": [{"register": "rip", "offset": 40, "value": "0x6161616b"}]
        }
        """.strip()
    )
    proof = tmp_path / "proof.json"
    proof.write_text(
        """
        {
          "id": "proof_crash_000001_pc",
          "level": 3,
          "claim": "controllable instruction pointer",
          "status": "verified"
        }
        """.strip()
    )

    report = build_exploit_chain_report(
        crash_report=crash,
        proof_report=proof,
        workspace=tmp_path,
    )

    assert "漏洞点" in report
    assert "攻击链" in report
    assert "crash_000001" in report
    assert "proof_crash_000001_pc" in report
    assert "rip" in report


def test_write_exploit_chain_report_writes_markdown(tmp_path: Path):
    crash = tmp_path / "crash.json"
    crash.write_text(
        """
        {
          "id": "crash_000001",
          "binary": "target/chall",
          "signal": "SIGSEGV",
          "controlled_registers": [{"register": "rip", "offset": 40, "value": "0x6161616b"}]
        }
        """.strip()
    )
    proof = tmp_path / "proof.json"
    proof.write_text(
        """
        {
          "id": "proof_crash_000001_pc",
          "level": 3,
          "claim": "controllable instruction pointer",
          "status": "verified"
        }
        """.strip()
    )
    output = tmp_path / "findings" / "exploit_chain_summary_000001.md"

    write_exploit_chain_report(
        output=output,
        crash_report=crash,
        proof_report=proof,
        workspace=tmp_path,
    )

    text = output.read_text()
    assert "# 漏洞点" in text
    assert "攻击链" in text
    assert "proof_crash_000001_pc" in text


def test_report_command_writes_output(tmp_path: Path):
    crash = tmp_path / "crash.json"
    crash.write_text(
        """
        {
          "id": "crash_000001",
          "binary": "target/chall",
          "signal": "SIGSEGV",
          "controlled_registers": [{"register": "rip", "offset": 40, "value": "0x6161616b"}]
        }
        """.strip()
    )
    proof = tmp_path / "proof.json"
    proof.write_text(
        """
        {
          "id": "proof_crash_000001_pc",
          "level": 3,
          "claim": "controllable instruction pointer",
          "status": "verified"
        }
        """.strip()
    )
    output = tmp_path / "findings" / "exploit_chain_summary_000002.md"

    text = write_exploit_chain_report(
        output=output,
        crash_report=crash,
        proof_report=proof,
        workspace=tmp_path,
    )

    assert output.exists()
    assert "漏洞点" in text
