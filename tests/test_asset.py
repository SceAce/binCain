import json
from pathlib import Path

from bincain.asset import ingest_seed
from bincain.tool_registry import ensure_tool_registry


def test_tool_registry_contains_required_tools(tmp_path: Path):
    registry = ensure_tool_registry(tmp_path / "workspace")
    ids = {tool["id"] for tool in registry["tools"]}

    assert {"bash", "gdb", "objdump", "r2", "bincain-init", "skill-search"}.issubset(ids)


def test_ingest_seed_records_asset_and_hint(tmp_path: Path):
    workspace = tmp_path / "workspace"
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"firmware_dir": "target", "hint": "Prefer web surface"}))

    result = ingest_seed(workspace=workspace, seed=seed)
    assets = json.loads((workspace / "findings" / "assets.json").read_text())
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())

    assert result["asset"]["kind"] == "firmware_dir"
    assert assets["assets"][0]["value"] == "target"
    assert assets["hints"][0]["content"] == "Prefer web surface"
    assert summary["iot_graph"]["hint_count"] == 1
