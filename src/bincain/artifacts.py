from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def append_event(
    workspace: Path | str,
    *,
    source: str,
    kind: str,
    summary: str,
    artifact: str | None = None,
    caused_by: str | None = None,
    related: list[str] | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace)
    findings_dir = workspace_path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    events_path = findings_dir / "events.jsonl"

    event = {
        "seq": _next_event_seq(events_path),
        "created_at": _utc_now(),
        "source": source,
        "kind": kind,
        "summary": summary,
        "artifact": artifact,
        "caused_by": caused_by,
        "related": related or [],
    }
    with events_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def update_summary(workspace: Path | str, **sections: Any) -> dict[str, Any]:
    workspace_path = Path(workspace)
    findings_dir = workspace_path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    summary_path = findings_dir / "summary_latest.json"

    summary = _default_summary(workspace_path)
    if summary_path.exists():
        summary.update(json.loads(summary_path.read_text(encoding="utf-8")))
    summary["latest_event_seq"] = _latest_event_seq(findings_dir / "events.jsonl")
    summary["updated_at"] = _utc_now()
    summary.update(sections)
    _atomic_write_json(summary_path, summary)
    return summary


def read_latest_summary(workspace: Path | str) -> dict[str, Any]:
    summary_path = Path(workspace) / "findings" / "summary_latest.json"
    return json.loads(summary_path.read_text(encoding="utf-8"))


def create_summary_snapshot(workspace: Path | str, summary: dict[str, Any] | None = None) -> Path:
    workspace_path = Path(workspace)
    if summary is None:
        summary = read_latest_summary(workspace_path)
    snapshots_dir = workspace_path / "findings" / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    seq = int(summary.get("latest_event_seq") or 0)
    snapshot_path = snapshots_dir / f"summary_{seq:06d}.json"
    _atomic_write_json(snapshot_path, summary)
    return snapshot_path


def _default_summary(workspace: Path) -> dict[str, Any]:
    return {
        "schema": "bincain.summary.v1",
        "workspace": str(workspace),
        "latest_event_seq": 0,
        "updated_at": None,
        "target": {},
        "run_profiles": {},
        "connection_profiles": {},
        "selected_crashes": [],
        "negative_results": [],
        "primitive_candidates": [],
        "protocol": {},
    }


def _next_event_seq(events_path: Path) -> int:
    return _latest_event_seq(events_path) + 1


def _latest_event_seq(events_path: Path) -> int:
    if not events_path.exists():
        return 0
    last_seq = 0
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        last_seq = int(json.loads(line)["seq"])
    return last_seq


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temp_path, path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
