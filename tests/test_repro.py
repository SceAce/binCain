import json
import os
from pathlib import Path

from bincain.repro import generate_repro


def test_generate_repro_writes_script_and_report(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "findings").mkdir(parents=True)
    (workspace / "scripts").mkdir()
    (workspace / "crashes").mkdir()
    (workspace / "findings" / "run_profiles.json").write_text(
        json.dumps({"schema": "bincain.run_profiles.v1", "default": "qemu", "profiles": {"qemu": {"argv": ["qemu-mipsel", "./chall"], "env": {}}}})
    )
    crash_input = workspace / "crashes" / "id_000001"
    crash_input.write_bytes(b"AAAA")
    crash_report = workspace / "findings" / "crash_000001.json"
    crash_report.write_text(
        json.dumps({"id": "crash_000001", "binary": "target/chall", "crash_input": str(crash_input)})
    )

    result = generate_repro(workspace=workspace, crash_report=crash_report)

    script = Path(result["script"])
    assert script.exists()
    assert os.access(script, os.X_OK)
    assert "run_target.sh --profile qemu" in script.read_text()
    assert result["profile"] == "qemu"
    assert Path(result["report"]).exists()
