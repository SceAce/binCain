import json
from pathlib import Path

from bincain.primitive import assert_leak, assert_pc


def test_assert_pc_verifies_controlled_register(tmp_path: Path):
    workspace = tmp_path / "workspace"
    crash = workspace / "findings" / "crash_000001.json"
    crash.parent.mkdir(parents=True)
    crash.write_text(
        json.dumps(
            {
                "id": "crash_000001",
                "binary": "target/chall",
                "controlled_registers": [{"register": "rip", "offset": 40}],
            }
        )
    )

    proof = assert_pc(workspace=workspace, crash_report=crash)

    assert proof["status"] == "verified"
    assert proof["level"] == 3
    assert Path(proof["path"]).exists()


def test_assert_leak_marks_candidate_inside_maps_as_verified(tmp_path: Path):
    workspace = tmp_path / "workspace"
    maps = tmp_path / "maps.txt"
    maps.write_text("7ffff7a00000-7ffff7c00000 r-xp 00000000 00:00 0 /lib/libc.so.6\n")

    proof = assert_leak(
        workspace=workspace,
        candidates=["0x7ffff7a12345"],
        maps_file=maps,
        reproducer="scripts/repro_leak.py",
    )

    assert proof["status"] == "verified"
    assert proof["level"] == 1
    assert proof["mapped_region"]["path"].endswith("libc.so.6")
