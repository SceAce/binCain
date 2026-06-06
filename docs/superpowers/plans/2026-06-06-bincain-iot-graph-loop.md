# binCain IoT Graph Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first AI-native IoT graph loop that can run 3 mock-AI rounds in Docker, render planner/executor/verifier prompts, and persist Fact/Intent/Hint-style progress.

**Architecture:** Add a new IoT loop slice that does not depend on CTF pwn modules. `bincain.iot_graph` owns graph artifact schemas, `bincain.ai_loop` owns prompt rendering and mock/agent providers, `bincain.iot_loop` coordinates rounds, and `bincain.asset` ingests seed assets. Existing `bincain.artifacts` is reused for events and summary because it is generic workspace state.

**Tech Stack:** Python 3.11, Click, pytest, JSON/Markdown artifacts, existing Docker worker.

---

## File Structure

- Create `src/bincain/iot_graph.py`: read/write `assets.json`, `hypotheses.json`, `verifications.json`, `long_tasks.json`, and graph summary helpers.
- Create `src/bincain/ai_loop.py`: render prompts, load prompt templates, define `MockAIProvider`, and reject unauthenticated real provider calls clearly.
- Create `src/bincain/tool_registry.py`: write `findings/tool_registry.json` with bash/gdb/objdump/r2/binCain helper/skill-search entries.
- Create `src/bincain/asset.py`: implement seed ingest into `assets.json` and summary.
- Create `src/bincain/iot_loop.py`: implement `run_iot_loop(..., rounds=3, ai_provider="mock")`.
- Modify `src/bincain/cli.py`: expose `binCain-loop` and `binCain-asset ingest`.
- Modify `pyproject.toml`: add `binCain-loop` and `binCain-asset` console scripts.
- Create prompt files under `integration/bincain/prompts/iot_loop/`: `planner.md`, `executor.md`, `verifier.md`.
- Modify `worker/Dockerfile`: assert new commands exist.
- Create tests: `tests/test_iot_graph.py`, `tests/test_ai_loop.py`, `tests/test_iot_loop.py`, `tests/test_asset.py`, `tests/test_iot_loop_contract.py`.
- Modify `tests/test_imports.py` and `tests/test_worker_dockerfile.py`.

## Task 1: Graph Artifact Schema

**Files:**
- Create: `tests/test_iot_graph.py`
- Create: `src/bincain/iot_graph.py`

- [ ] **Step 1: Write failing tests for graph initialization and hint persistence**

```python
import json
from pathlib import Path

from bincain.iot_graph import ensure_iot_graph, add_hint, add_hypothesis, add_fact


def test_ensure_iot_graph_creates_empty_state_files(tmp_path: Path):
    workspace = tmp_path / "workspace"
    graph = ensure_iot_graph(workspace)

    assert graph["facts"] == []
    assert graph["intents"] == []
    assert graph["hints"] == []
    assert (workspace / "findings" / "assets.json").exists()
    assert (workspace / "findings" / "hypotheses.json").exists()
    assert (workspace / "findings" / "verifications.json").exists()
    assert (workspace / "findings" / "long_tasks.json").exists()


def test_graph_records_fact_intent_and_hint(tmp_path: Path):
    workspace = tmp_path / "workspace"
    add_fact(workspace, description="Seed path exists", evidence=["findings/assets.json"])
    add_hypothesis(workspace, description="Enumerate target entrypoints", source="seed")
    add_hint(workspace, content="Prefer local firmware analysis")

    graph = ensure_iot_graph(workspace)
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())

    assert graph["facts"][0]["description"] == "Seed path exists"
    assert graph["intents"][0]["description"] == "Enumerate target entrypoints"
    assert graph["hints"][0]["content"] == "Prefer local firmware analysis"
    assert summary["iot_graph"]["fact_count"] == 1
    assert summary["iot_graph"]["intent_count"] == 1
    assert summary["iot_graph"]["hint_count"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_iot_graph.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'bincain.iot_graph'`.

- [ ] **Step 3: Implement graph artifact helpers**

Create `src/bincain/iot_graph.py` with functions:

```python
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bincain.artifacts import append_event, update_summary


def ensure_iot_graph(workspace: Path | str) -> dict[str, Any]:
    workspace_path = Path(workspace)
    findings = workspace_path / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    _ensure_json(findings / "assets.json", {"schema": "bincain.assets.v1", "assets": []})
    _ensure_json(findings / "hypotheses.json", {"schema": "bincain.hypotheses.v1", "items": []})
    _ensure_json(findings / "verifications.json", {"schema": "bincain.verifications.v1", "items": []})
    _ensure_json(findings / "long_tasks.json", {"schema": "bincain.long_tasks.v1", "tasks": []})
    return _graph_view(workspace_path)


def add_fact(workspace: Path | str, *, description: str, evidence: list[str] | None = None, confidence: str = "medium") -> dict[str, Any]:
    workspace_path = Path(workspace)
    verifications = _read_json(workspace_path / "findings" / "verifications.json") if (workspace_path / "findings" / "verifications.json").exists() else {"schema": "bincain.verifications.v1", "items": []}
    item = _record("fact", description=description, evidence=evidence or [], confidence=confidence)
    verifications["items"].append(item)
    _write_json(workspace_path / "findings" / "verifications.json", verifications)
    append_event(workspace_path, source="binCain-loop", kind="fact_verified", summary=description, artifact="findings/verifications.json", related=evidence or [])
    _refresh_summary(workspace_path)
    return item


def add_hypothesis(workspace: Path | str, *, description: str, source: str = "planner", evidence: list[str] | None = None) -> dict[str, Any]:
    workspace_path = Path(workspace)
    hypotheses = _read_json(workspace_path / "findings" / "hypotheses.json") if (workspace_path / "findings" / "hypotheses.json").exists() else {"schema": "bincain.hypotheses.v1", "items": []}
    item = _record("intent", description=description, source=source, evidence=evidence or [], status="pending")
    hypotheses["items"].append(item)
    _write_json(workspace_path / "findings" / "hypotheses.json", hypotheses)
    append_event(workspace_path, source="binCain-loop", kind="intent_created", summary=description, artifact="findings/hypotheses.json", related=evidence or [])
    _refresh_summary(workspace_path)
    return item


def add_hint(workspace: Path | str, *, content: str) -> dict[str, Any]:
    workspace_path = Path(workspace)
    assets = _read_json(workspace_path / "findings" / "assets.json") if (workspace_path / "findings" / "assets.json").exists() else {"schema": "bincain.assets.v1", "assets": []}
    hints = assets.setdefault("hints", [])
    item = {"id": f"hint_{len(hints) + 1:06d}", "content": content, "created_at": _now()}
    hints.append(item)
    _write_json(workspace_path / "findings" / "assets.json", assets)
    append_event(workspace_path, source="binCain-asset", kind="hint_recorded", summary=content, artifact="findings/assets.json")
    _refresh_summary(workspace_path)
    return item
```

- [ ] **Step 4: Run graph tests to verify pass**

Run: `python -m pytest tests/test_iot_graph.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/iot_graph.py tests/test_iot_graph.py
git commit -m "Add IoT graph artifact state"
```

## Task 2: Prompt Rendering and AI Providers

**Files:**
- Create: `tests/test_ai_loop.py`
- Create: `src/bincain/ai_loop.py`
- Create: `integration/bincain/prompts/iot_loop/planner.md`
- Create: `integration/bincain/prompts/iot_loop/executor.md`
- Create: `integration/bincain/prompts/iot_loop/verifier.md`

- [ ] **Step 1: Write failing tests for prompt rendering, mock provider, and agent auth failure**

```python
import pytest

from bincain.ai_loop import AgentProvider, MockAIProvider, render_prompt


def test_render_prompt_includes_graph_and_tool_registry():
    prompt = render_prompt(
        "planner",
        {
            "round": 1,
            "summary": {"iot_graph": {"intent_count": 0}},
            "graph": {"facts": [], "intents": [], "hints": []},
            "tool_registry": {"tools": [{"id": "bash"}]},
        },
    )

    assert "已知事实" in prompt
    assert '"round": 1' in prompt
    assert "bash" in prompt


def test_mock_provider_returns_structured_outputs():
    provider = MockAIProvider()

    plan = provider.complete(role="planner", prompt="round 1")
    execution = provider.complete(role="executor", prompt="run")
    verification = provider.complete(role="verifier", prompt="verify")

    assert plan["tool_request"]["tool_id"] == "bash"
    assert execution["artifact"].startswith("findings/")
    assert verification["facts"]


def test_agent_provider_requires_authenticated_backend():
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", authenticated=False)

    with pytest.raises(RuntimeError, match="AI provider is not authenticated"):
        provider.complete(role="planner", prompt="hello")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_ai_loop.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'bincain.ai_loop'`.

- [ ] **Step 3: Add prompt files with strict JSON contracts**

Create the three prompt files and include:
- planner explains graph semantics and JSON output.
- executor explains authorized tool execution and artifact output.
- verifier explains fact/intent/hint upgrade and JSON output.

- [ ] **Step 4: Implement prompt renderer and providers**

Create `src/bincain/ai_loop.py` with:
- `render_prompt(role, context)`
- `MockAIProvider.complete(role, prompt)`
- `AgentProvider.complete(role, prompt)` that raises clear auth error when `authenticated=False`.

- [ ] **Step 5: Run AI loop tests to verify pass**

Run: `python -m pytest tests/test_ai_loop.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/bincain/ai_loop.py tests/test_ai_loop.py integration/bincain/prompts/iot_loop
git commit -m "Add AI loop prompts and providers"
```

## Task 3: Tool Registry and Asset Ingest

**Files:**
- Create: `tests/test_asset.py`
- Create: `src/bincain/tool_registry.py`
- Create: `src/bincain/asset.py`

- [ ] **Step 1: Write failing tests for tool registry and seed ingest**

```python
import json
from pathlib import Path

from bincain.asset import ingest_seed
from bincain.tool_registry import ensure_tool_registry


def test_tool_registry_contains_required_tools(tmp_path: Path):
    registry = ensure_tool_registry(tmp_path / "workspace")
    ids = {tool["id"] for tool in registry["tools"]}

    assert {"bash", "gdb", "objdump", "r2", "bincain-init", "skill-search"}.issubset(ids)


def test_ingest_seed_records_asset_and_hint(tmp_path: Path):
    workspace = tmp_path / "workspace"
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"firmware_dir": "target", "hint": "Prefer web surface"}))

    result = ingest_seed(workspace=workspace, seed=seed)
    assets = json.loads((workspace / "findings" / "assets.json").read_text())
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())

    assert result["asset"]["kind"] == "firmware_dir"
    assert assets["assets"][0]["value"] == "target"
    assert assets["hints"][0]["content"] == "Prefer web surface"
    assert summary["iot_graph"]["hint_count"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_asset.py -q`
Expected: FAIL with missing modules.

- [ ] **Step 3: Implement registry and ingest**

Implement:
- `ensure_tool_registry(workspace)`
- `ingest_seed(workspace, seed)`

- [ ] **Step 4: Run asset tests to verify pass**

Run: `python -m pytest tests/test_asset.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/tool_registry.py src/bincain/asset.py tests/test_asset.py
git commit -m "Add IoT asset ingest and tool registry"
```

## Task 4: Three-Round Loop Runner and CLI

**Files:**
- Create: `tests/test_iot_loop.py`
- Create: `src/bincain/iot_loop.py`
- Modify: `src/bincain/cli.py`
- Modify: `pyproject.toml`
- Modify: `tests/test_imports.py`

- [ ] **Step 1: Write failing tests for 3-round loop and CLI scripts**

```python
import json
from pathlib import Path

from click.testing import CliRunner

from bincain.cli import loop_cmd
from bincain.iot_loop import run_iot_loop


def test_run_iot_loop_advances_three_rounds(tmp_path: Path):
    workspace = tmp_path / "workspace"
    result = run_iot_loop(workspace=workspace, rounds=3, ai_provider="mock")

    events = (workspace / "findings" / "events.jsonl").read_text().splitlines()
    summary = json.loads((workspace / "findings" / "summary_latest.json").read_text())
    hypotheses = json.loads((workspace / "findings" / "hypotheses.json").read_text())
    verifications = json.loads((workspace / "findings" / "verifications.json").read_text())

    assert result["rounds_completed"] == 3
    assert summary["iot_graph"]["round"] == 3
    assert len(events) >= 3
    assert len(hypotheses["items"]) >= 1
    assert len(verifications["items"]) >= 1


def test_loop_command_runs_mock_provider(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(loop_cmd, ["--workspace", str(tmp_path / "workspace"), "--rounds", "3", "--ai-provider", "mock"])

    assert result.exit_code == 0
    assert '"rounds_completed": 3' in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_iot_loop.py -q`
Expected: FAIL with missing `bincain.iot_loop` or `loop_cmd`.

- [ ] **Step 3: Implement loop runner and CLI**

Implement:
- `run_iot_loop(workspace, rounds, ai_provider, planner, executor, verifier)`
- `loop_cmd`
- `asset_cmd` group with `ingest`
- `binCain-loop` and `binCain-asset` scripts in `pyproject.toml`

- [ ] **Step 4: Run loop tests and import tests**

Run: `python -m pytest tests/test_iot_loop.py tests/test_imports.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/bincain/iot_loop.py src/bincain/cli.py pyproject.toml tests/test_iot_loop.py tests/test_imports.py
git commit -m "Add IoT graph loop CLI"
```

## Task 5: Contract Tests and Docker Surface

**Files:**
- Create: `tests/test_iot_loop_contract.py`
- Modify: `tests/test_worker_dockerfile.py`
- Modify: `worker/Dockerfile`

- [ ] **Step 1: Write failing contract tests**

```python
from pathlib import Path


def test_iot_loop_prompts_exist_and_define_json_outputs():
    prompt_dir = Path("integration/bincain/prompts/iot_loop")
    for name in ["planner.md", "executor.md", "verifier.md"]:
        text = (prompt_dir / name).read_text()
        assert "JSON" in text
        assert "Fact" in text or "已知事实" in text
        assert "Intent" in text or "待验证" in text


def test_worker_dockerfile_checks_iot_loop_commands():
    text = Path("worker/Dockerfile").read_text()
    assert "binCain-loop --help" in text
    assert "binCain-asset --help" in text
```

- [ ] **Step 2: Run tests to verify Dockerfile assertion fails**

Run: `python -m pytest tests/test_iot_loop_contract.py tests/test_worker_dockerfile.py -q`
Expected: FAIL until Dockerfile checks are added.

- [ ] **Step 3: Update Dockerfile command checks**

Add:

```dockerfile
    && binCain-loop --help >/dev/null \
    && binCain-asset --help >/dev/null \
```

- [ ] **Step 4: Run contract tests**

Run: `python -m pytest tests/test_iot_loop_contract.py tests/test_worker_dockerfile.py -q`
Expected: PASS.

- [ ] **Step 5: Run full test suite**

Run: `python -m pytest -q`
Expected: PASS with the existing skipped Docker smoke if Docker is unavailable.

- [ ] **Step 6: Commit**

```bash
git add tests/test_iot_loop_contract.py tests/test_worker_dockerfile.py worker/Dockerfile
git commit -m "Cover IoT loop worker contract"
```

