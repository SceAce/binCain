import json
from pathlib import Path

from bincain.protocol import generate_protocol_template


def test_generate_protocol_template_from_menu_topology(tmp_path: Path):
    workspace = tmp_path / "workspace"
    topology = {
        "prompt": "> ",
        "actions": {
            "1": {"name": "add", "fields": ["size", "data"]},
            "2": {"name": "delete", "fields": ["index"]},
        },
        "source": "human Hint h003",
    }

    result = generate_protocol_template(workspace, topology)

    script = Path(result["script"])
    assert script.exists()
    assert "def add" in script.read_text()
    assert "def delete" in script.read_text()
    saved = json.loads((workspace / "findings" / "protocol_topology.json").read_text())
    assert saved["source"] == "human Hint h003"
