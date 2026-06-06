from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bincain.ai_loop import AgentProvider, MockAIProvider, render_prompt
from bincain.artifacts import append_event, read_latest_summary, update_summary
from bincain.iot_graph import add_fact, add_hypothesis, ensure_iot_graph, graph_summary
from bincain.tool_registry import ensure_tool_registry


def run_iot_loop(
    *,
    workspace: Path | str,
    rounds: int = 3,
    ai_provider: str = "mock",
    planner: str = "codex",
    executor: str = "codex",
    verifier: str = "claude",
) -> dict[str, Any]:
    workspace_path = Path(workspace)
    provider = _provider(ai_provider, planner=planner, executor=executor, verifier=verifier)
    prompts_rendered = 0
    last_plan: dict[str, Any] | None = None
    last_execution: dict[str, Any] | None = None
    last_verification: dict[str, Any] | None = None

    ensure_iot_graph(workspace_path)
    registry = ensure_tool_registry(workspace_path)

    for round_number in range(1, rounds + 1):
        graph = ensure_iot_graph(workspace_path)
        summary = _read_summary_or_empty(workspace_path)
        planner_prompt = render_prompt("planner", _context(round_number, graph, summary, registry))
        prompts_rendered += 1
        plan = provider.complete(role="planner", prompt=planner_prompt)

        executor_prompt = render_prompt(
            "executor",
            _context(round_number, graph, summary, registry, planner_output=plan),
        )
        prompts_rendered += 1
        execution = provider.complete(role="executor", prompt=executor_prompt)
        artifact = _write_execution_artifact(workspace_path, round_number, plan, execution)
        _write_long_task_observation(workspace_path, round_number, execution)

        verifier_prompt = render_prompt(
            "verifier",
            _context(round_number, graph, summary, registry, planner_output=plan, executor_output=execution),
        )
        prompts_rendered += 1
        verification = provider.complete(role="verifier", prompt=verifier_prompt)
        _apply_verification(workspace_path, verification, artifact)
        _refresh_round_summary(workspace_path, round_number, prompts_rendered)
        append_event(
            workspace_path,
            source="binCain-loop",
            kind="round_completed",
            summary=f"IoT graph loop round {round_number} completed",
            artifact=artifact,
        )
        last_plan = plan
        last_execution = execution
        last_verification = verification

    return {
        "rounds_completed": rounds,
        "ai_provider": ai_provider,
        "prompts_rendered": prompts_rendered,
        "last_plan": last_plan,
        "last_execution": last_execution,
        "last_verification": last_verification,
    }


def _provider(ai_provider: str, *, planner: str, executor: str, verifier: str) -> MockAIProvider | AgentProvider:
    if ai_provider == "mock":
        return MockAIProvider()
    if ai_provider == "agent":
        return AgentProvider(planner=planner, executor=executor, verifier=verifier, authenticated=False)
    raise ValueError(f"unsupported AI provider: {ai_provider}")


def _context(
    round_number: int,
    graph: dict[str, Any],
    summary: dict[str, Any],
    registry: dict[str, Any],
    **extra: Any,
) -> dict[str, Any]:
    return {
        "round": round_number,
        "graph": graph,
        "summary": summary,
        "tool_registry": registry,
        **extra,
    }


def _write_execution_artifact(workspace: Path, round_number: int, plan: dict[str, Any], execution: dict[str, Any]) -> str:
    path = workspace / "findings" / f"round_{round_number:06d}_executor.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"planner": plan, "executor": execution}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return f"findings/{path.name}"


def _apply_verification(workspace: Path, verification: dict[str, Any], artifact: str) -> None:
    for fact in verification.get("facts", []):
        evidence = list(fact.get("evidence") or [artifact])
        add_fact(
            workspace,
            description=str(fact.get("description", "Verified loop evidence")),
            evidence=evidence,
            confidence=str(fact.get("confidence", "medium")),
        )
    for item in verification.get("new_hypotheses", []):
        add_hypothesis(
            workspace,
            description=str(item.get("description", "Continue IoT graph loop verification")),
            source=str(item.get("source", "verifier")),
            evidence=[artifact],
        )
    _record_verification(workspace, verification, artifact)
    for item in verification.get("pending", []):
        add_hypothesis(
            workspace,
            description=str(item.get("description", "Continue pending IoT verification")),
            source=str(item.get("source", "verifier")),
            evidence=[artifact],
        )


def _record_verification(workspace: Path, verification: dict[str, Any], artifact: str) -> None:
    path = workspace / "findings" / "verifications.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.setdefault("items", [])
    items.append(
        {
            "id": f"verification_{len(items) + 1:06d}",
            "type": "verification",
            "artifact": artifact,
            "facts": verification.get("facts", []),
            "rejected": verification.get("rejected", []),
            "pending": verification.get("pending", []),
            "new_hypotheses": verification.get("new_hypotheses", []),
            "value": verification.get("value", {}),
        }
    )
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_long_task_observation(workspace: Path, round_number: int, execution: dict[str, Any]) -> None:
    path = workspace / "findings" / "long_tasks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["last_observed_round"] = round_number
    data["last_executor_status"] = execution.get("status")
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_round_summary(workspace: Path, round_number: int, prompts_rendered: int) -> None:
    summary = graph_summary(workspace)
    summary["round"] = round_number
    summary["prompts_rendered"] = prompts_rendered
    update_summary(workspace, iot_graph=summary)


def _read_summary_or_empty(workspace: Path) -> dict[str, Any]:
    try:
        return read_latest_summary(workspace)
    except FileNotFoundError:
        return {}
