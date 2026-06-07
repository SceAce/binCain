import json
from pathlib import Path

import pytest
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
    long_tasks = json.loads((workspace / "findings" / "long_tasks.json").read_text())

    assert result["rounds_completed"] == 3
    assert result["last_plan"]["chosen_intent"].endswith("round 3")
    assert summary["iot_graph"]["round"] == 3
    assert len(events) >= 3
    assert len(hypotheses["items"]) >= 1
    assert len(verifications["items"]) >= 1
    assert any(item.get("type") == "verification" for item in verifications["items"])
    assert verifications["items"][-1]["value"]["level"] == "service exposure"
    assert long_tasks["last_observed_round"] == 3


def test_loop_command_runs_mock_provider(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(loop_cmd, ["--workspace", str(tmp_path / "workspace"), "--rounds", "3", "--ai-provider", "mock"])

    assert result.exit_code == 0
    assert '"rounds_completed": 3' in result.output


def test_agent_loop_requires_allow_real_ai(tmp_path: Path):
    with pytest.raises(RuntimeError, match="--allow-real-ai"):
        run_iot_loop(workspace=tmp_path / "workspace", rounds=1, ai_provider="agent")


def test_loop_command_accepts_agent_config_and_backend_options(monkeypatch, tmp_path: Path):
    captured = {}
    config = tmp_path / "dispatch.yaml"
    config.write_text("workers: []\n", encoding="utf-8")

    def fake_run_iot_loop(**kwargs):
        captured.update(kwargs)
        return {"rounds_completed": 0, "ai_provider": kwargs["ai_provider"], "prompts_rendered": 0}

    monkeypatch.setattr("bincain.iot_cli.run_iot_loop", fake_run_iot_loop)
    runner = CliRunner()
    result = runner.invoke(
        loop_cmd,
        [
            "--workspace",
            str(tmp_path / "workspace"),
            "--ai-provider",
            "agent",
            "--allow-real-ai",
            "--ai-config",
            str(config),
            "--planner-backend",
            "thinker-claude",
            "--executor-backend",
            "doer-codex",
            "--verifier-backend",
            "thinker-claude",
            "--ai-timeout",
            "23",
        ],
    )

    assert result.exit_code == 0
    assert captured["allow_real_ai"] is True
    assert captured["ai_config"] == str(config)
    assert captured["planner_backend"] == "thinker-claude"
    assert captured["executor_backend"] == "doer-codex"
    assert captured["verifier_backend"] == "thinker-claude"
    assert captured["ai_timeout"] == 23
