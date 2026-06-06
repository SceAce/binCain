from __future__ import annotations

import json
import subprocess
from importlib import resources
from typing import Any


PROMPT_PACKAGE = "bincain.prompts.iot_loop"
VALID_ROLES = {"planner", "executor", "verifier"}


def render_prompt(role: str, context: dict[str, Any]) -> str:
    _validate_role(role)
    template = resources.files(PROMPT_PACKAGE).joinpath(f"{role}.md").read_text(encoding="utf-8")
    context_json = json.dumps(context, indent=2, sort_keys=True, ensure_ascii=False)
    return template.replace("{context_json}", context_json)


class MockAIProvider:
    def complete(self, *, role: str, prompt: str) -> dict[str, Any]:
        _validate_role(role)
        round_number = _extract_round(prompt)
        if role == "planner":
            return {
                "chosen_intent": f"Enumerate target entrypoints for round {round_number}",
                "reason": f"Round {round_number} should use the current graph state to produce fresh evidence.",
                "tool_request": {
                    "tool_id": "bash",
                    "arguments": {"command": f"find target -maxdepth {round_number + 1} -type f"},
                    "expected_artifact": f"findings/mock_executor_round_{round_number}.json",
                    "risk": "low",
                    "long_running": False,
                },
                "expected_evidence": [f"findings/mock_executor_round_{round_number}.json"],
                "new_hypotheses": [f"Validate discovered entrypoints from round {round_number}"],
            }
        if role == "executor":
            return {
                "status": "completed",
                "artifact": f"findings/mock_executor_round_{round_number}.json",
                "summary": f"Mock executor observed a target entrypoint candidate in round {round_number}.",
                "failure_reason": None,
                "observations": [f"target entrypoint candidate exists in round {round_number}"],
            }
        return {
            "facts": [
                {
                    "description": f"Mock executor completed one evidence-producing action in round {round_number}",
                    "evidence": [f"findings/mock_executor_round_{round_number}.json"],
                    "confidence": "medium",
                }
            ],
            "rejected": [],
            "pending": [{"description": f"Continue observing target state after round {round_number}", "source": "verifier"}],
            "new_hypotheses": [{"description": f"Validate target entrypoint candidate from round {round_number}", "source": "verifier"}],
            "value": {"level": "service exposure", "reason": f"Round {round_number} produced reachable-entrypoint style evidence."},
        }


class AgentProvider:
    def __init__(
        self,
        *,
        planner: str = "codex",
        executor: str = "codex",
        verifier: str = "claude",
        authenticated: bool = False,
    ) -> None:
        self.backends = {"planner": planner, "executor": executor, "verifier": verifier}
        self.authenticated = authenticated

    def complete(self, *, role: str, prompt: str) -> dict[str, Any]:
        _validate_role(role)
        if not self.authenticated:
            raise RuntimeError("AI provider is not authenticated; use --ai-provider mock for local loop validation")
        backend = self.backends[role]
        completed = subprocess.run(
            _command_for_backend(backend, prompt),
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"AI backend {backend} failed: {completed.stderr.strip()}")
        return json.loads(completed.stdout)


def _command_for_backend(backend: str, prompt: str) -> list[str]:
    if backend == "codex":
        return ["codex", "exec", "--json", prompt]
    if backend in {"claude", "claude-code"}:
        return ["claude", "-p", prompt]
    raise ValueError(f"unsupported AI backend: {backend}")


def _validate_role(role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError(f"invalid AI loop role: {role}")


def _extract_round(prompt: str) -> int:
    marker = "Context JSON:"
    if marker not in prompt:
        return 1
    json_text = prompt.split(marker, 1)[1].strip()
    try:
        context, _ = json.JSONDecoder().raw_decode(json_text)
        return int(context.get("round") or 1)
    except (json.JSONDecodeError, TypeError, ValueError):
        return 1
