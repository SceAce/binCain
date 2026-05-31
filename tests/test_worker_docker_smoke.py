import os
import shutil
import subprocess
from pathlib import Path

import pytest

from bincain.cyclic import cyclic


pytestmark = pytest.mark.skipif(
    os.environ.get("BINCAIN_DOCKER_TEST") != "1",
    reason="set BINCAIN_DOCKER_TEST=1 to run Docker worker smoke test",
)


def test_worker_container_runs_real_gdb_triage_chain(tmp_path: Path):
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    if shutil.which("gcc") is None:
        pytest.skip("gcc is not installed")

    repo = Path.cwd()
    image = "bincain-worker:dev"
    fixture_src = repo / "tests" / "fixtures" / "pwn" / "controlled_pc.c"
    target_dir = tmp_path / "target"
    crashes_dir = tmp_path / "crashes"
    target_dir.mkdir()
    crashes_dir.mkdir()
    subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-z", "execstack", "-o", str(target_dir / "chall"), str(fixture_src)],
        check=True,
    )
    (crashes_dir / "id_000001").write_bytes(cyclic(80))

    subprocess.run(["docker", "build", "-f", "worker/Dockerfile", "-t", image, "."], cwd=repo, check=True)
    command = """
set -euo pipefail
cp -a /mnt/target/. /home/kali/workspace/target/
cp -a /mnt/crashes/. /home/kali/workspace/crashes/
binCain-init /home/kali/workspace/target --workspace /home/kali/workspace
binCain-triage --binary /home/kali/workspace/target/chall --input /home/kali/workspace/crashes/id_000001 --output /home/kali/workspace/findings/crash_000001.json --arch amd64 --workspace /home/kali/workspace --gdb
binCain-repro --workspace /home/kali/workspace --crash-report /home/kali/workspace/findings/crash_000001.json
binCain-primitive assert-pc --workspace /home/kali/workspace --crash /home/kali/workspace/findings/crash_000001.json
test -f /home/kali/workspace/proofs/proof_crash_000001_pc.json
grep -q primitive_asserted /home/kali/workspace/findings/events.jsonl
grep -q primitive_candidates /home/kali/workspace/findings/summary_latest.json
"""
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{target_dir}:/mnt/target:ro",
            "-v",
            f"{crashes_dir}:/mnt/crashes:ro",
            image,
            "bash",
            "-lc",
            command,
        ],
        check=True,
    )
