from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, update_summary


def generate_repro(*, workspace: Path | str, crash_report: Path | str, profile: str | None = None) -> dict[str, Any]:
    workspace_path = Path(workspace)
    report_path = Path(crash_report)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    crash_id = report.get("id") or report_path.stem
    scripts_dir = workspace_path / "scripts"
    findings_dir = workspace_path / "findings"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    findings_dir.mkdir(parents=True, exist_ok=True)
    selected_profile = profile or _default_profile(workspace_path)

    script_path = scripts_dir / f"repro_{crash_id}.sh"
    crash_input = report["crash_input"]
    script = f"""#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec scripts/run_target.sh --profile {selected_profile} < {json.dumps(crash_input)}
"""
    script_path.write_text(script)
    script_path.chmod(0o755)

    result = {
        "schema": "bincain.repro.v1",
        "id": f"repro_{crash_id}",
        "crash": str(report_path),
        "script": str(script_path),
        "profile": selected_profile,
        "report": str(findings_dir / f"repro_{crash_id}.json"),
    }
    Path(result["report"]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    append_event(
        workspace_path,
        source="binCain-repro",
        kind="repro_generated",
        summary=f"Generated replay script for {crash_id} using profile {selected_profile}",
        artifact=_workspace_relative(workspace_path, script_path),
        caused_by=_workspace_relative(workspace_path, report_path),
    )
    update_summary(
        workspace_path,
        reproducers=[
            {
                "id": result["id"],
                "script": _workspace_relative(workspace_path, script_path),
                "crash": _workspace_relative(workspace_path, report_path),
                "profile": selected_profile,
            }
        ],
    )
    return result


def _workspace_relative(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _default_profile(workspace: Path) -> str:
    run_profiles_path = workspace / "findings" / "run_profiles.json"
    if not run_profiles_path.exists():
        return "raw"
    data = json.loads(run_profiles_path.read_text(encoding="utf-8"))
    profile = data.get("default")
    return str(profile) if profile else "raw"
