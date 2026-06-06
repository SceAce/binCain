from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_TOOLS = [
    {
        "id": "bash",
        "kind": "cli",
        "risk": "low",
        "description": "Controlled local shell commands for file, find, readelf, strings, timeout, and similar inspection.",
    },
    {
        "id": "gdb",
        "kind": "cli",
        "risk": "medium",
        "description": "gdb or gdb-multiarch debugging and crash inspection.",
    },
    {
        "id": "objdump",
        "kind": "cli",
        "risk": "low",
        "description": "objdump/readelf disassembly and metadata inspection.",
    },
    {
        "id": "r2",
        "kind": "cli",
        "risk": "low",
        "description": "radare2 or rizin static analysis.",
    },
    {
        "id": "bincain-init",
        "kind": "helper",
        "risk": "low",
        "description": "Generic target measurement helper.",
    },
    {
        "id": "skill-search",
        "kind": "skill",
        "risk": "medium",
        "description": "Placeholder for FOFA, search, OSINT, or other asset-discovery skills.",
    },
]


def ensure_tool_registry(workspace: Path | str) -> dict[str, Any]:
    workspace_path = Path(workspace)
    path = workspace_path / "findings" / "tool_registry.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    registry = {"schema": "bincain.tool_registry.v1", "tools": DEFAULT_TOOLS}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry
