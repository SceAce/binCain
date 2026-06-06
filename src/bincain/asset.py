from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bincain.iot_graph import add_asset, add_hint, add_hypothesis, ensure_iot_graph


SEED_KEYS = ("firmware_dir", "firmware_file", "ip", "domain", "fofa_json")


def ingest_seed(*, workspace: Path | str, seed: Path | str) -> dict[str, Any]:
    workspace_path = Path(workspace)
    ensure_iot_graph(workspace_path)
    data = json.loads(Path(seed).read_text(encoding="utf-8"))
    asset = _asset_from_seed(workspace_path, data)
    hint = add_hint(workspace_path, content=str(data["hint"])) if data.get("hint") else None
    intent = add_hypothesis(workspace_path, description=f"Enumerate entrypoints for {asset['kind']} {asset['value']}", source="seed")
    return {"asset": asset, "hint": hint, "intent": intent}


def _asset_from_seed(workspace: Path, data: dict[str, Any]) -> dict[str, Any]:
    for key in SEED_KEYS:
        if key in data and data[key]:
            return add_asset(workspace, kind=key, value=str(data[key]), source="seed")
    raise ValueError("seed must include one of firmware_dir, firmware_file, ip, domain, or fofa_json")
