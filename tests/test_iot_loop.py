import json
from pathlib import Path

from click.testing import CliRunner

from bincain.cli import loop_cmd
from bincain.iot_loop import run_iot_loop


def test_run_iot_loop_advances_three_rounds(tmp_path: Path):
    workspace = tmp_path / "workspace"
    result = run_iot_loop(workspace=workspace, rounds=3, ai_provider="mock")

    events = (workspace / "findings" / "events.jsonl").read_text().splitlines()
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())
    hypotheses = json.loads((workspace / "findings" / "hypotheses.json").read_text())
    verifications = json.loads((workspace / "findings" / "verifications.json").read_text())

    assert result["rounds_completed"] == 3
    assert summary["iot_graph"]["round"] == 3
    assert len(events) >= 3
    assert len(hypotheses["items"]) >= 1
    assert len(verifications["items"]) >= 1


def test_loop_command_runs_mock_provider(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(loop_cmd, ["--workspace", str(tmp_path / "workspace"), "--rounds", "3", "--ai-provider", "mock"])

    assert result.exit_code == 0
    assert '"rounds_completed": 3' in result.output
