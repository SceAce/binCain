# binCain V1 Worker Scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first testable binCain worker-side scaffold: Python package, `binCain-init`, `binCain-triage`, pwn agent guidance, and tests.

**Architecture:** Start with worker-local tools because they provide the highest return without changing Cairn-style Server or Dispatcher semantics. The CLI scripts emit compact JSON and filesystem artifacts that future agent prompts can reference as Facts.

**Tech Stack:** Python 3.11+, pytest, pyproject console scripts, pwntools-compatible cyclic helpers with a local fallback, GDB batch script generation.

---

## File Structure

- Create `pyproject.toml`: project metadata, console scripts, pytest config.
- Create `src/bincain/__init__.py`: package version.
- Create `src/bincain/init.py`: challenge artifact discovery, libc/ld metadata, run wrapper generation, JSON output.
- Create `src/bincain/triage.py`: crash triage report builder, cyclic match analysis, optional GDB batch invocation.
- Create `src/bincain/cyclic.py`: dependency-light cyclic pattern generation and offset lookup.
- Create `src/bincain/cli.py`: console entrypoints for `binCain-init` and `binCain-triage`.
- Create `worker/AGENTS.md`: pwn worker instructions, primitive hierarchy, tool guardrails.
- Create `worker/templates/menu_action_fuzzer.py`: editable pwntools action mutator template.
- Create `tests/test_cyclic.py`: cyclic helper tests.
- Create `tests/test_init.py`: `binCain-init` behavior tests.
- Create `tests/test_triage.py`: `binCain-triage` report behavior tests.

## Task 1: Project Skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `src/bincain/__init__.py`
- Create: `src/bincain/cli.py`
- Test: `tests/test_imports.py`

- [ ] **Step 1: Write the failing import and CLI metadata test**

```python
from bincain import __version__
from bincain.cli import main


def test_package_exposes_version_and_cli_group():
    assert isinstance(__version__, str)
    assert __version__
    assert callable(main)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_imports.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'bincain'`.

- [ ] **Step 3: Add minimal package skeleton**

Create `pyproject.toml` with package metadata, pytest config, and console scripts.
Create `src/bincain/__init__.py` with `__version__ = "0.1.0"`.
Create `src/bincain/cli.py` with a callable Click command group.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_imports.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

Run:
```bash
git add pyproject.toml src/bincain/__init__.py src/bincain/cli.py tests/test_imports.py
git commit -m "Add Python project skeleton"
```

## Task 2: Cyclic Pattern Helpers

**Files:**
- Create: `src/bincain/cyclic.py`
- Test: `tests/test_cyclic.py`

- [ ] **Step 1: Write failing tests for cyclic generation and offset lookup**

```python
from bincain.cyclic import cyclic, cyclic_find


def test_cyclic_generates_stable_unique_pattern_prefix():
    assert cyclic(12) == b"aaaabaaacaaa"


def test_cyclic_find_accepts_bytes_and_little_endian_ints():
    pattern = cyclic(128)
    needle = pattern[40:44]

    assert cyclic_find(needle) == 40
    assert cyclic_find(int.from_bytes(needle, "little"), width=4) == 40
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cyclic.py -q`
Expected: FAIL because `bincain.cyclic` does not exist.

- [ ] **Step 3: Implement minimal cyclic helpers**

Implement lowercase triplet cyclic generation compatible with common pwn offsets and `cyclic_find` for bytes and little-endian integers.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cyclic.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

Run:
```bash
git add src/bincain/cyclic.py tests/test_cyclic.py
git commit -m "Add cyclic pattern helpers"
```

## Task 3: binCain-init

**Files:**
- Create: `src/bincain/init.py`
- Modify: `src/bincain/cli.py`
- Test: `tests/test_init.py`

- [ ] **Step 1: Write failing tests for artifact discovery and run wrapper generation**

```python
import json
import os
from pathlib import Path

from bincain.init import init_challenge


def test_init_challenge_writes_metadata_and_run_wrapper(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    binary = target / "chall"
    binary.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 32)
    binary.chmod(0o755)
    (target / "libc.so.6").write_bytes(b"fake libc")

    workspace = tmp_path / "workspace"
    result = init_challenge(target, workspace)

    init_json = workspace / "findings" / "init.json"
    run_wrapper = workspace / "scripts" / "run_chall.sh"

    assert result["binaries"][0]["path"].endswith("target/chall")
    assert result["libc_candidates"][0].endswith("target/libc.so.6")
    assert init_json.exists()
    assert run_wrapper.exists()
    assert os.access(run_wrapper, os.X_OK)

    saved = json.loads(init_json.read_text())
    assert saved["workspace"] == str(workspace)
    assert saved["run_wrappers"][0]["path"] == str(run_wrapper)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_init.py -q`
Expected: FAIL because `bincain.init` does not exist.

- [ ] **Step 3: Implement minimal `init_challenge`**

Implement directory creation, executable/ELF detection, libc/ld candidate discovery, executable run wrapper creation, and `findings/init.json` writing. Do not download loaders in V1 scaffold; report that patching was not attempted unless `pwninit` is available.

- [ ] **Step 4: Add CLI command and run tests**

Expose `binCain-init TARGET --workspace WORKSPACE`.
Run: `python -m pytest tests/test_init.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

Run:
```bash
git add src/bincain/init.py src/bincain/cli.py tests/test_init.py
git commit -m "Add binCain init helper"
```

## Task 4: binCain-triage

**Files:**
- Create: `src/bincain/triage.py`
- Modify: `src/bincain/cli.py`
- Test: `tests/test_triage.py`

- [ ] **Step 1: Write failing tests for compact crash report generation**

```python
import json
from pathlib import Path

from bincain.cyclic import cyclic
from bincain.triage import build_crash_report, write_crash_report


def test_build_crash_report_detects_cyclic_register_offsets(tmp_path: Path):
    crash_input = tmp_path / "crash.bin"
    crash_input.write_bytes(cyclic(128))

    report = build_crash_report(
        binary="target/chall",
        crash_input=crash_input,
        arch="amd64",
        signal="SIGSEGV",
        registers={"rip": "0x6161616b", "rsp": "0x7fffffffd000"},
        backtrace=["main+42"],
    )

    assert report["binary"] == "target/chall"
    assert report["controlled_registers"][0]["register"] == "rip"
    assert report["controlled_registers"][0]["offset"] == 40


def test_write_crash_report_writes_json(tmp_path: Path):
    crash_input = tmp_path / "crash.bin"
    crash_input.write_bytes(cyclic(64))
    output = tmp_path / "report.json"

    write_crash_report(
        output=output,
        binary="target/chall",
        crash_input=crash_input,
        arch="i386",
        signal="SIGSEGV",
        registers={"eip": "0x61616166"},
        backtrace=[],
    )

    saved = json.loads(output.read_text())
    assert saved["arch"] == "i386"
    assert saved["controlled_registers"][0]["register"] == "eip"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_triage.py -q`
Expected: FAIL because `bincain.triage` does not exist.

- [ ] **Step 3: Implement compact report generation**

Implement report generation from provided register data and crash input. Generate GDB command text separately, but keep actual GDB execution optional for this scaffold.

- [ ] **Step 4: Add CLI command and run tests**

Expose `binCain-triage --binary BINARY --input CRASH --output REPORT`.
Run: `python -m pytest tests/test_triage.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

Run:
```bash
git add src/bincain/triage.py src/bincain/cli.py tests/test_triage.py
git commit -m "Add binCain crash triage helper"
```

## Task 5: Worker Guidance and Fuzz Template

**Files:**
- Create: `worker/AGENTS.md`
- Create: `worker/templates/menu_action_fuzzer.py`
- Test: `tests/test_worker_docs.py`

- [ ] **Step 1: Write failing tests for required worker guidance**

```python
from pathlib import Path


def test_worker_agents_mentions_primitives_and_angr_guardrail():
    text = Path("worker/AGENTS.md").read_text()

    assert "Level 1" in text
    assert "Level 2" in text
    assert "Level 3" in text
    assert "Do not invoke angr in the first triage round" in text


def test_menu_action_fuzzer_template_has_mutation_entrypoint():
    text = Path("worker/templates/menu_action_fuzzer.py").read_text()

    assert "def mutate_actions" in text
    assert "def run_case" in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_worker_docs.py -q`
Expected: FAIL because files do not exist.

- [ ] **Step 3: Add worker guidance and template**

Create concise `AGENTS.md` with workspace layout, primitive hierarchy, evidence format, fuzz policy, and heavy-tool guardrails.
Create an editable pwntools action mutator template with `mutate_actions` and `run_case`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_worker_docs.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

Run:
```bash
git add worker/AGENTS.md worker/templates/menu_action_fuzzer.py tests/test_worker_docs.py
git commit -m "Add pwn worker guidance and templates"
```

## Task 6: Full Verification

**Files:**
- Modify only if verification exposes a defect.

- [ ] **Step 1: Run all tests**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 2: Check git status**

Run: `git status --short`
Expected: clean working tree.

- [ ] **Step 3: Push commits if requested**

Run only when the user asks: `git push -u origin main`

## Self-Review

Spec coverage:

- Worker helper scripts are covered by Tasks 3 and 4.
- Primitive hierarchy and tool guardrails are covered by Task 5.
- Hybrid fuzz support starts with the menu action mutator template in Task 5.
- Server/Dispatcher implementation is intentionally deferred; this plan creates the V1 worker scaffold first.

No placeholders are left in implementation steps. Type names are consistent across tasks.
