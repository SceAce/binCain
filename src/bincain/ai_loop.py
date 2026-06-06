from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


PROMPT_DIR = Path(__file__).resolve().parents[2] / "integration" / "bincain" / "prompts" / "iot_loop"
VALID_ROLES = {"planner", "executor", "verifier"}


def render_prompt(role: str, context: dict[str, Any]) -> str:
    _validate_role(role)
    template = (PROMPT_DIR / f"{role}.md").read_text(encoding="utf-8")
    context_json = json.dumps(context, indent=2, sort_keys=True, ensure_ascii=False)
    return template.replace("{context_json}", context_json)


class MockAIProvider:
    def complete(self, *, role: str, prompt: str) -> dict[str, Any]:
        _validate_role(role)
        if role == "planner":
            return {
                "chosen_intent": "Enumerate target entrypoints",
                "reason": "The first useful step is to discover observable files and services from the seed.",
                "tool_request": {
                    "tool_id": "bash",
                    "arguments": {"command": "find target -maxdepth 2 -type f"},
                    "expected_artifact": "findings/mock_executor.json",
                    "risk": "low",
                    "long_running": False,
                },
                "expected_evidence": ["findings/mock_executor.json"],
                "new_hypotheses": ["Validate discovered entrypoints"],
            }
        if role == "executor":
            return {
                "status": "completed",
                "artifact": "findings/mock_executor.json",
                "summary": "Mock executor observed a target entrypoint candidate.",
                "failure_reason": None,
                "observations": ["target entrypoint candidate exists"],
            }
        return {
            "facts": [
                {
                    "description": "Mock executor completed one evidence-producing action",
                    "evidence": ["findings/mock_executor.json"],
                    "confidence": "medium",
                }
            ],
            "rejected": [],
            "pending": [],
            "new_hypotheses": [{"description": "Validate target entrypoint candidate", "source": "verifier"}],
            "value": {"level": "service exposure", "reason": "A reachable entrypoint candidate is useful follow-up evidence."},
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
