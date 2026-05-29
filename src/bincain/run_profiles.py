from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_run_profiles(binary: Path | str) -> dict[str, Any]:
    binary_path = str(Path(binary))
    return {
        "schema": "bincain.run_profiles.v1",
        "default": "raw",
        "profiles": {
            "raw": {
                "argv": [binary_path],
                "env": {},
                "stdin": True,
                "notes": "Minimal local execution.",
            },
            "debug": {
                "argv": ["gdb", "-q", "--args", binary_path],
                "env": {},
                "stdin": True,
                "notes": "Debugger-friendly execution.",
            },
            "fuzz": {
                "argv": [binary_path],
                "env": {},
                "stdin": True,
                "notes": "Clean local execution for fuzzing wrappers.",
            },
        },
    }


def build_connection_profiles() -> dict[str, Any]:
    return {
        "schema": "bincain.connection_profiles.v1",
        "profiles": {},
    }


def write_run_target_wrapper(scripts_dir: Path | str, run_profiles_path: Path | str) -> Path:
    scripts_path = Path(scripts_dir)
    scripts_path.mkdir(parents=True, exist_ok=True)
    profiles_path = Path(run_profiles_path)
    wrapper = scripts_path / "run_target.sh"
    script = f"""#!/usr/bin/env bash
set -euo pipefail

profile="raw"
if [[ "${{1:-}}" == "--profile" ]]; then
  profile="${{2:-raw}}"
  shift 2
fi

python3 - "$profile" {json.dumps(str(profiles_path))} "$@" <<'PY'
import json
import os
import subprocess
import sys

profile = sys.argv[1]
profiles_path = sys.argv[2]
extra = sys.argv[3:]
data = json.load(open(profiles_path, encoding="utf-8"))
profiles = data.get("profiles", {{}})
if profile not in profiles:
    raise SystemExit(f"unknown run profile: {{profile}}")
entry = profiles[profile]
argv = list(entry.get("argv", [])) + extra
env = os.environ.copy()
env.update(entry.get("env", {{}}))
raise SystemExit(subprocess.call(argv, env=env))
PY
"""
    wrapper.write_text(script)
    wrapper.chmod(0o755)
    return wrapper
