# binCain Operational Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the operational hardening spec as worker-side tools and artifact contracts without changing Cairn protocol semantics.

**Architecture:** Add focused Python modules for artifact events/summaries, run profiles, repro generation, protocol templates, and primitive assertions. Existing `init` and `triage` helpers become producers of append-only events and compact summaries, while CLI commands expose the new affordances.

**Tech Stack:** Python 3.11+, pytest, click, JSON/JSONL artifacts, shell wrapper generation.

---

## File Structure

- Create `src/bincain/artifacts.py`: append-only event log, atomic summary writes, snapshot helper, workspace path helpers.
- Create `src/bincain/run_profiles.py`: run profile and connection profile builders plus `scripts/run_target.sh` generation.
- Modify `src/bincain/init.py`: create full workspace layout, run profiles, connection profiles, events, summaries.
- Modify `src/bincain/triage.py`: event/summary integration and optional crash id handling.
- Create `src/bincain/repro.py`: generate replay scripts from crash reports and run profiles.
- Create `src/bincain/protocol.py`: convert menu topology into `scripts/base_interaction.py`.
- Create `src/bincain/primitive.py`: assertion result generation for PC/offset/leak/write primitives.
- Modify `src/bincain/cli.py`: expose `repro`, `protocol-template`, and `primitive` commands.
- Modify `worker/AGENTS.md`: document run profiles, event summaries, falsifiable Intents, and primitive assertions.
- Create tests for each module under `tests/`.

## Task 1: Artifact Event Log and Summary Infrastructure

**Files:**
- Create: `src/bincain/artifacts.py`
- Test: `tests/test_artifacts.py`

- [ ] **Step 1: Write failing tests**

```python
import json
from pathlib import Path

from bincain.artifacts import append_event, create_summary_snapshot, read_latest_summary, update_summary


def test_append_event_allocates_sequence_and_writes_jsonl(tmp_path: Path):
    workspace = tmp_path / "workspace"

    first = append_event(workspace, source="binCain-init", kind="initialized", summary="baseline ready")
    second = append_event(workspace, source="binCain-triage", kind="crash_triaged", summary="crash ready", artifact="findings/crash_000001.json")

    events = (workspace / "findings" / "events.jsonl").read_text().splitlines()
    assert first["seq"] == 1
    assert second["seq"] == 2
    assert json.loads(events[0])["kind"] == "initialized"
    assert json.loads(events[1])["artifact"] == "findings/crash_000001.json"


def test_update_summary_writes_latest_atomically_and_snapshot(tmp_path: Path):
    workspace = tmp_path / "workspace"
    event = append_event(workspace, source="binCain-init", kind="initialized", summary="baseline ready")

    summary = update_summary(
        workspace,
        target={"path": "target/chall"},
        run_profiles={"default": "raw"},
        selected_crashes=[{"id": "crash_000001", "summary": "rip control"}],
    )
    snapshot = create_summary_snapshot(workspace, summary)

    latest = read_latest_summary(workspace)
    assert latest["latest_event_seq"] == event["seq"]
    assert latest["target"]["path"] == "target/chall"
    assert latest["selected_crashes"][0]["id"] == "crash_000001"
    assert snapshot.name == "summary_000001.json"
    assert json.loads(snapshot.read_text())["latest_event_seq"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python -m pytest tests/test_artifacts.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'bincain.artifacts'`.

- [ ] **Step 3: Implement `artifacts.py`**

Implement:

```python
def append_event(workspace, *, source, kind, summary, artifact=None, caused_by=None, related=None) -> dict: ...
def update_summary(workspace, **sections) -> dict: ...
def read_latest_summary(workspace) -> dict: ...
def create_summary_snapshot(workspace, summary=None) -> Path: ...
```

Use append-only `findings/events.jsonl`, monotonic `seq`, atomic write via temp file plus `replace`, and stable default summary fields.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_artifacts.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/bincain/artifacts.py tests/test_artifacts.py
git commit -m "Add artifact event log and summary helpers"
```

## Task 2: Run Profiles and Hardened Init

**Files:**
- Create: `src/bincain/run_profiles.py`
- Modify: `src/bincain/init.py`
- Test: `tests/test_run_profiles.py`
- Modify: `tests/test_init.py`

- [ ] **Step 1: Write failing tests**

Add tests that:

```python
import json
import os
from pathlib import Path

from bincain.init import init_challenge
from bincain.run_profiles import build_run_profiles, write_run_target_wrapper


def test_build_run_profiles_creates_raw_debug_and_fuzz_profiles(tmp_path: Path):
    binary = tmp_path / "chall"
    binary.write_bytes(b"\x7fELF")
    profiles = build_run_profiles(binary)
    assert profiles["schema"] == "bincain.run_profiles.v1"
    assert profiles["default"] == "raw"
    assert {"raw", "debug", "fuzz"}.issubset(profiles["profiles"])


def test_write_run_target_wrapper_uses_profile_argument(tmp_path: Path):
    wrapper = write_run_target_wrapper(tmp_path / "scripts", tmp_path / "findings" / "run_profiles.json")
    text = wrapper.read_text()
    assert "--profile" in text
    assert "run_profiles.json" in text
    assert os.access(wrapper, os.X_OK)


def test_init_writes_run_profiles_connection_profiles_events_and_summary(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 32)
    binary.chmod(0o755)

    workspace = tmp_path / "workspace"
    init_challenge(target, workspace)

    assert (workspace / "findings" / "run_profiles.json").exists()
    assert (workspace / "findings" / "connection_profiles.json").exists()
    assert (workspace / "scripts" / "run_target.sh").exists()
    assert (workspace / "findings" / "events.jsonl").exists()
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())
    assert summary["run_profiles"]["default"] == "raw"
    assert summary["target"]["path"] == str(target.resolve())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python -m pytest tests/test_run_profiles.py tests/test_init.py -q`
Expected: FAIL because `bincain.run_profiles` is missing and init does not write profile artifacts.

- [ ] **Step 3: Implement run profiles and init integration**

Create run profile builders, write `run_target.sh`, create workspace dirs `target`, `scripts`, `fuzz`, `crashes`, `findings`, `notes`, `proofs`, and update init to append an `initialized` event and `summary_latest.json`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_run_profiles.py tests/test_init.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/run_profiles.py src/bincain/init.py tests/test_run_profiles.py tests/test_init.py
git commit -m "Add run profiles to binCain init"
```

## Task 3: Triage Events and Summary Integration

**Files:**
- Modify: `src/bincain/triage.py`
- Test: `tests/test_triage.py`

- [ ] **Step 1: Write failing test**

Add:

```python
import json
from pathlib import Path

from bincain.cyclic import cyclic
from bincain.triage import write_crash_report


def test_write_crash_report_updates_workspace_events_and_summary(tmp_path: Path):
    workspace = tmp_path / "workspace"
    crash_input = workspace / "crashes" / "id_000001"
    crash_input.parent.mkdir(parents=True)
    crash_input.write_bytes(cyclic(128))
    output = workspace / "findings" / "crash_000001.json"

    report = write_crash_report(
        output=output,
        binary="target/chall",
        crash_input=crash_input,
        arch="amd64",
        signal="SIGSEGV",
        registers={"rip": "0x6161616b"},
        workspace=workspace,
    )

    assert report["id"] == "crash_000001"
    events = (workspace / "findings" / "events.jsonl").read_text()
    assert "crash_triaged" in events
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())
    assert summary["selected_crashes"][0]["id"] == "crash_000001"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_triage.py -q`
Expected: FAIL because `write_crash_report` has no `workspace` parameter and report has no `id`.

- [ ] **Step 3: Implement triage integration**

Add optional `workspace` and `crash_id` parameters, infer crash id from output stem, append `crash_triaged` event, update selected crash summary, and preserve existing behavior when `workspace` is omitted.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_triage.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/triage.py tests/test_triage.py
git commit -m "Record triage events and summaries"
```

## Task 4: Repro Helper

**Files:**
- Create: `src/bincain/repro.py`
- Modify: `src/bincain/cli.py`
- Test: `tests/test_repro.py`

- [ ] **Step 1: Write failing tests**

Create tests for:

```python
import json
import os
from pathlib import Path

from bincain.repro import generate_repro


def test_generate_repro_writes_script_and_report(tmp_path: Path):
    workspace = tmp_path / "workspace"
    (workspace / "findings").mkdir(parents=True)
    (workspace / "scripts").mkdir()
    (workspace / "crashes").mkdir()
    crash_input = workspace / "crashes" / "id_000001"
    crash_input.write_bytes(b"AAAA")
    crash_report = workspace / "findings" / "crash_000001.json"
    crash_report.write_text(json.dumps({"id": "crash_000001", "binary": "target/chall", "crash_input": str(crash_input)}))

    result = generate_repro(workspace=workspace, crash_report=crash_report)

    script = Path(result["script"])
    assert script.exists()
    assert os.access(script, os.X_OK)
    assert "run_target.sh --profile raw" in script.read_text()
    assert Path(result["report"]).exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_repro.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement repro helper and CLI**

Implement `generate_repro(workspace, crash_report, profile="raw")`, write `scripts/repro_<id>.sh`, write `findings/repro_<id>.json`, append a `repro_generated` event, and add `binCain repro --workspace WORKSPACE --crash-report REPORT`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_repro.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/repro.py src/bincain/cli.py tests/test_repro.py
git commit -m "Add crash repro helper"
```

## Task 5: Protocol Template Helper

**Files:**
- Create: `src/bincain/protocol.py`
- Modify: `src/bincain/cli.py`
- Test: `tests/test_protocol.py`

- [ ] **Step 1: Write failing tests**

Create tests for:

```python
import json
from pathlib import Path

from bincain.protocol import generate_protocol_template


def test_generate_protocol_template_from_menu_topology(tmp_path: Path):
    workspace = tmp_path / "workspace"
    topology = {
        "prompt": "> ",
        "actions": {
            "1": {"name": "add", "fields": ["size", "data"]},
            "2": {"name": "delete", "fields": ["index"]},
        },
        "source": "human Hint h003",
    }

    result = generate_protocol_template(workspace, topology)

    script = Path(result["script"])
    assert script.exists()
    assert "def add" in script.read_text()
    assert "def delete" in script.read_text()
    saved = json.loads((workspace / "findings" / "protocol_topology.json").read_text())
    assert saved["source"] == "human Hint h003"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_protocol.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement protocol helper and CLI**

Implement topology JSON saving, `scripts/base_interaction.py` generation with pwntools helpers, summary update, and `binCain protocol-template --workspace WORKSPACE --topology TOPOLOGY_JSON`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_protocol.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/protocol.py src/bincain/cli.py tests/test_protocol.py
git commit -m "Add protocol template helper"
```

## Task 6: Primitive Assertion Helper

**Files:**
- Create: `src/bincain/primitive.py`
- Modify: `src/bincain/cli.py`
- Test: `tests/test_primitive.py`

- [ ] **Step 1: Write failing tests**

Create tests for:

```python
import json
from pathlib import Path

from bincain.primitive import assert_leak, assert_pc


def test_assert_pc_verifies_controlled_register(tmp_path: Path):
    workspace = tmp_path / "workspace"
    crash = workspace / "findings" / "crash_000001.json"
    crash.parent.mkdir(parents=True)
    crash.write_text(json.dumps({"id": "crash_000001", "binary": "target/chall", "controlled_registers": [{"register": "rip", "offset": 40}]}))

    proof = assert_pc(workspace=workspace, crash_report=crash)

    assert proof["status"] == "verified"
    assert proof["level"] == 3
    assert Path(proof["path"]).exists()


def test_assert_leak_marks_candidate_inside_maps_as_verified(tmp_path: Path):
    workspace = tmp_path / "workspace"
    maps = tmp_path / "maps.txt"
    maps.write_text("7ffff7a00000-7ffff7c00000 r-xp 00000000 00:00 0 /lib/libc.so.6\n")

    proof = assert_leak(workspace=workspace, candidates=["0x7ffff7a12345"], maps_file=maps, reproducer="scripts/repro_leak.py")

    assert proof["status"] == "verified"
    assert proof["level"] == 1
    assert proof["mapped_region"]["path"].endswith("libc.so.6")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m pytest tests/test_primitive.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement primitive helper and CLI**

Implement `assert_pc`, `assert_offset`, `assert_leak`, and simple `assert_write` proof artifact generation. Status must be one of `verified`, `plausible`, `unverified`, `rejected`. Add CLI group `primitive`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_primitive.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/primitive.py src/bincain/cli.py tests/test_primitive.py
git commit -m "Add primitive assertion helper"
```

## Task 7: CLI and Worker Guidance Integration

**Files:**
- Modify: `src/bincain/cli.py`
- Modify: `worker/AGENTS.md`
- Test: `tests/test_imports.py`
- Test: `tests/test_worker_docs.py`

- [ ] **Step 1: Write failing tests**

Add CLI import assertions:

```python
from click.testing import CliRunner

from bincain.cli import main


def test_cli_lists_operational_hardening_commands():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "repro" in result.output
    assert "protocol-template" in result.output
    assert "primitive" in result.output
```

Add worker docs assertions:

```python
from pathlib import Path


def test_worker_docs_describe_run_profiles_events_and_falsifiable_intents():
    text = Path("worker/AGENTS.md").read_text()
    assert "run_target.sh --profile" in text
    assert "events.jsonl" in text
    assert "summary_latest.json" in text
    assert "falsifiable" in text.lower()
    assert "binCain-primitive" in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python -m pytest tests/test_imports.py tests/test_worker_docs.py -q`
Expected: FAIL until CLI/docs are updated.

- [ ] **Step 3: Implement CLI/docs integration**

Ensure `main` lists all commands and worker guidance documents run profiles, event summaries, falsifiable Intents, human Hint acceleration, and primitive assertions.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python -m pytest tests/test_imports.py tests/test_worker_docs.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/cli.py worker/AGENTS.md tests/test_imports.py tests/test_worker_docs.py
git commit -m "Document operational hardening workflow"
```

## Task 8: Full Verification

**Files:**
- All modified files

- [ ] **Step 1: Run full test suite**

Run: `PYTHONPATH=src python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 2: Verify git status**

Run: `git status --short --branch`
Expected: clean worktree on `bincain-operational-hardening`.

- [ ] **Step 3: Review spec coverage**

Check `docs/superpowers/specs/2026-05-29-bincain-operational-hardening-design.md` against implemented behavior:

- Run profiles exist.
- Connection profiles exist.
- Event log exists.
- Atomic summary exists.
- Repro helper exists.
- Protocol template exists.
- Primitive assertions exist.
- Worker prompt guidance exists.

