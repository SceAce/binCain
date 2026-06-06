from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, update_summary


def ensure_iot_graph(workspace: Path | str) -> dict[str, Any]:
    workspace_path = Path(workspace)
    findings_dir = workspace_path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    _ensure_json(findings_dir / "assets.json", {"schema": "bincain.assets.v1", "assets": [], "hints": []})
    _ensure_json(findings_dir / "hypotheses.json", {"schema": "bincain.hypotheses.v1", "items": []})
    _ensure_json(findings_dir / "verifications.json", {"schema": "bincain.verifications.v1", "items": []})
    _ensure_json(findings_dir / "long_tasks.json", {"schema": "bincain.long_tasks.v1", "tasks": []})
    graph = _graph_view(workspace_path)
    _refresh_summary(workspace_path, graph)
    return graph


def add_fact(
    workspace: Path | str,
    *,
    description: str,
    evidence: list[str] | None = None,
    confidence: str = "medium",
) -> dict[str, Any]:
    workspace_path = Path(workspace)
    ensure_iot_graph(workspace_path)
    path = workspace_path / "findings" / "verifications.json"
    data = _read_json(path)
    item = _record("fact", description=description, evidence=evidence or [], confidence=confidence)
    data["items"].append(item)
    _write_json(path, data)
    append_event(
        workspace_path,
        source="binCain-loop",
        kind="fact_verified",
        summary=description,
        artifact="findings/verifications.json",
        related=evidence or [],
    )
    _refresh_summary(workspace_path)
    return item


def add_hypothesis(
    workspace: Path | str,
    *,
    description: str,
    source: str = "planner",
    evidence: list[str] | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace)
    ensure_iot_graph(workspace_path)
    path = workspace_path / "findings" / "hypotheses.json"
    data = _read_json(path)
    item = _record("intent", description=description, source=source, evidence=evidence or [], status="pending")
    data["items"].append(item)
    _write_json(path, data)
    append_event(
        workspace_path,
        source="binCain-loop",
        kind="intent_created",
        summary=description,
        artifact="findings/hypotheses.json",
        related=evidence or [],
    )
    _refresh_summary(workspace_path)
    return item


def add_hint(workspace: Path | str, *, content: str) -> dict[str, Any]:
    workspace_path = Path(workspace)
    ensure_iot_graph(workspace_path)
    path = workspace_path / "findings" / "assets.json"
    data = _read_json(path)
    hints = data.setdefault("hints", [])
    item = {"id": f"hint_{len(hints) + 1:06d}", "content": content, "created_at": _now()}
    hints.append(item)
    _write_json(path, data)
    append_event(workspace_path, source="binCain-asset", kind="hint_recorded", summary=content, artifact="findings/assets.json")
    _refresh_summary(workspace_path)
    return item


def add_asset(workspace: Path | str, *, kind: str, value: str, source: str = "seed") -> dict[str, Any]:
    workspace_path = Path(workspace)
    ensure_iot_graph(workspace_path)
    path = workspace_path / "findings" / "assets.json"
    data = _read_json(path)
    assets = data.setdefault("assets", [])
    item = {
        "id": f"asset_{len(assets) + 1:06d}",
        "kind": kind,
        "value": value,
        "source": source,
        "created_at": _now(),
    }
    assets.append(item)
    _write_json(path, data)
    append_event(workspace_path, source="binCain-asset", kind="asset_ingested", summary=f"{kind}: {value}", artifact="findings/assets.json")
    _refresh_summary(workspace_path)
    return item


def graph_summary(workspace: Path | str) -> dict[str, Any]:
    graph = _graph_view(Path(workspace))
    return {
        "fact_count": len(graph["facts"]),
        "intent_count": len(graph["intents"]),
        "hint_count": len(graph["hints"]),
        "asset_count": len(graph["assets"]),
    }


def _graph_view(workspace: Path) -> dict[str, Any]:
    findings_dir = workspace / "findings"
    assets = _read_json(findings_dir / "assets.json")
    hypotheses = _read_json(findings_dir / "hypotheses.json")
    verifications = _read_json(findings_dir / "verifications.json")
    return {
        "facts": [item for item in verifications.get("items", []) if item.get("type") == "fact"],
        "intents": [item for item in hypotheses.get("items", []) if item.get("type") == "intent" and item.get("status") == "pending"],
        "hints": assets.get("hints", []),
        "assets": assets.get("assets", []),
    }


def _refresh_summary(workspace: Path, graph: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    if graph is None:
        graph = _graph_view(workspace)
    summary = {
        "fact_count": len(graph["facts"]),
        "intent_count": len(graph["intents"]),
        "hint_count": len(graph["hints"]),
        "asset_count": len(graph["assets"]),
    }
    summary.update(extra)
    return update_summary(workspace, iot_graph=summary)


def _record(record_type: str, **fields: Any) -> dict[str, Any]:
    return {
        "id": f"{record_type}_{_compact_now()}",
        "type": record_type,
        "created_at": _now(),
        **fields,
    }


def _ensure_json(path: Path, default: dict[str, Any]) -> None:
    if not path.exists():
        _write_json(path, default)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compact_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
