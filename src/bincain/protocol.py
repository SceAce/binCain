from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, update_summary


def generate_protocol_template(workspace: Path | str, topology: dict[str, Any]) -> dict[str, Any]:
    workspace_path = Path(workspace)
    findings_dir = workspace_path / "findings"
    scripts_dir = workspace_path / "scripts"
    findings_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir.mkdir(parents=True, exist_ok=True)

    topology_path = findings_dir / "protocol_topology.json"
    topology_path.write_text(json.dumps(topology, indent=2, sort_keys=True) + "\n")
    script_path = scripts_dir / "base_interaction.py"
    script_path.write_text(_render_template(topology))
    script_path.chmod(0o755)

    source = topology.get("source", "unknown")
    action_names = [
        str(action.get("name", key))
        for key, action in sorted(topology.get("actions", {}).items())
        if isinstance(action, dict)
    ]
    summary = f"Generated protocol template from {source}: {', '.join(action_names) or 'no actions'}."
    append_event(
        workspace_path,
        source="binCain-protocol",
        kind="protocol_template_generated",
        summary=summary,
        artifact="scripts/base_interaction.py",
        related=["findings/protocol_topology.json"],
    )
    update_summary(
        workspace_path,
        protocol={
            "topology": "findings/protocol_topology.json",
            "template": "scripts/base_interaction.py",
            "source": source,
            "actions": action_names,
        },
    )
    return {"script": str(script_path), "topology": str(topology_path), "summary": summary}


def _render_template(topology: dict[str, Any]) -> str:
    prompt = topology.get("prompt", "> ")
    functions = []
    for choice, action in sorted(topology.get("actions", {}).items()):
        if not isinstance(action, dict):
            continue
        name = _safe_identifier(str(action.get("name", f"action_{choice}")))
        fields = [str(field) for field in action.get("fields", [])]
        args = ", ".join(fields)
        lines = [
            f"def {name}(io, {args}):" if args else f"def {name}(io):",
            f"    io.sendlineafter({prompt!r}, {str(choice).encode()!r})",
        ]
        for field in fields:
            lines.append(f"    io.sendline(str({field}).encode())")
        functions.append("\n".join(lines))
    body = "\n\n\n".join(functions) if functions else "def interact(io):\n    return io.recvrepeat(0.1)"
    return f"""#!/usr/bin/env python3
from __future__ import annotations

from pwn import process, remote


def connect(binary=None, host=None, port=None):
    if host and port:
        return remote(host, int(port))
    if binary is None:
        binary = "target/chall"
    return process([binary])


{body}
"""


def _safe_identifier(value: str) -> str:
    result = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in value.strip().lower())
    if not result:
        return "action"
    if result[0].isdigit():
        return "action_" + result
    return result
