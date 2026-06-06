import json
from pathlib import Path

from bincain.iot_graph import add_fact, add_hint, add_hypothesis, ensure_iot_graph


def test_ensure_iot_graph_creates_empty_state_files(tmp_path: Path):
    workspace = tmp_path / "workspace"
    graph = ensure_iot_graph(workspace)

    assert graph["facts"] == []
    assert graph["intents"] == []
    assert graph["hints"] == []
    assert (workspace / "findings" / "assets.json").exists()
    assert (workspace / "findings" / "hypotheses.json").exists()
    assert (workspace / "findings" / "verifications.json").exists()
    assert (workspace / "findings" / "long_tasks.json").exists()


def test_graph_records_fact_intent_and_hint(tmp_path: Path):
    workspace = tmp_path / "workspace"
    add_fact(workspace, description="Seed path exists", evidence=["findings/assets.json"])
    add_hypothesis(workspace, description="Enumerate target entrypoints", source="seed")
    add_hint(workspace, content="Prefer local firmware analysis")

    graph = ensure_iot_graph(workspace)
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())

    assert graph["facts"][0]["description"] == "Seed path exists"
    assert graph["intents"][0]["description"] == "Enumerate target entrypoints"
    assert graph["hints"][0]["content"] == "Prefer local firmware analysis"
    assert summary["iot_graph"]["fact_count"] == 1
    assert summary["iot_graph"]["intent_count"] == 1
    assert summary["iot_graph"]["hint_count"] == 1
