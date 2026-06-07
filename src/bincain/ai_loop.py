from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


PROMPT_PACKAGE = "bincain.prompts.iot_loop"
VALID_ROLES = {"planner", "executor", "verifier"}
ROLE_TASK_ALIASES = {
    "planner": ("planner", "reason", "bootstrap"),
    "executor": ("executor", "explore"),
    "verifier": ("verifier", "reason", "bootstrap"),
}
REQUIRED_RESPONSE_FIELDS = {
    "planner": ("chosen_intent", "reason", "tool_request"),
    "executor": ("status", "artifact", "summary"),
    "verifier": ("facts", "rejected", "pending", "new_hypotheses", "value"),
}
CLI_ENVELOPE_TEXT_FIELDS = ("result", "content", "message", "text", "output")


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


@dataclass(frozen=True)
class AIBackendConfig:
    name: str
    backend_type: str
    env: dict[str, str]

    def __repr__(self) -> str:
        return f"AIBackendConfig(name={self.name!r}, backend_type={self.backend_type!r}, env_keys={sorted(self.env)})"


@dataclass(frozen=True)
class AIConfig:
    workers: tuple[AIBackendConfig, ...]
    task_types: dict[str, tuple[str, ...]]

    def resolve_backends(
        self,
        *,
        planner_backend: str | None,
        executor_backend: str | None,
        verifier_backend: str | None,
    ) -> dict[str, AIBackendConfig]:
        overrides = {
            "planner": planner_backend,
            "executor": executor_backend,
            "verifier": verifier_backend,
        }
        return {role: self.resolve_backend(role, overrides[role]) for role in VALID_ROLES}

    def resolve_backend(self, role: str, override: str | None = None) -> AIBackendConfig:
        _validate_role(role)
        if override:
            by_name = self._worker_by_name(override)
            if by_name is not None:
                return by_name
            return AIBackendConfig(name=override, backend_type=_normalize_backend_type(override), env={})

        for task_type in ROLE_TASK_ALIASES[role]:
            worker = self._worker_for_task_type(task_type)
            if worker is not None:
                return worker
        by_name = self._worker_by_name(role)
        if by_name is not None:
            return by_name
        raise ValueError(f"no AI backend configured for {role}; pass --{role}-backend or add a matching worker")

    def _worker_by_name(self, name: str) -> AIBackendConfig | None:
        for worker in self.workers:
            if worker.name == name:
                return worker
        return None

    def _worker_for_task_type(self, task_type: str) -> AIBackendConfig | None:
        for worker in self.workers:
            if task_type in self.task_types.get(worker.name, ()):
                return worker
        return None


class AgentProvider:
    def __init__(
        self,
        *,
        planner: str = "codex",
        executor: str = "codex",
        verifier: str = "claude",
        authenticated: bool | None = None,
        allow_real_ai: bool = False,
        timeout: int | float | None = None,
        cwd: Path | str | None = None,
        env_by_role: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.backends = {"planner": planner, "executor": executor, "verifier": verifier}
        self.allow_real_ai = allow_real_ai if authenticated is None else authenticated
        self.timeout = timeout
        self.cwd = str(cwd) if cwd is not None else None
        self.env_by_role = env_by_role or {}

    def complete(self, *, role: str, prompt: str) -> dict[str, Any]:
        _validate_role(role)
        backend = self.backends[role]
        backend_type = _normalize_backend_type(backend)
        if backend_type == "local":
            if role != "executor":
                raise RuntimeError(f"local backend only supports executor role; got role {role}")
            response = self._complete_local_executor(prompt)
            _validate_response_schema(role, response)
            return response
        if not self.allow_real_ai:
            raise RuntimeError("Real AI provider is disabled; pass --allow-real-ai or use --ai-provider mock")
        try:
            completed = subprocess.run(
                _command_for_backend(backend, prompt),
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.cwd,
                env=_merged_env(self.env_by_role.get(role, {})),
            )
        except subprocess.TimeoutExpired as exc:
            _write_ai_debug_artifact(
                cwd=self.cwd,
                backend=backend,
                role=role,
                round_number=_extract_round(prompt),
                returncode=None,
                stdout=_coerce_text(exc.stdout),
                stderr=_coerce_text(exc.stderr),
            )
            raise RuntimeError(
                f"AI backend {backend} timed out for role {role} after {exc.timeout} seconds"
            ) from exc
        _write_ai_debug_artifact(
            cwd=self.cwd,
            backend=backend,
            role=role,
            round_number=_extract_round(prompt),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(f"AI backend {backend} failed with exit code {completed.returncode}: {stderr}")
        response = parse_ai_stdout(completed.stdout)
        response = _normalize_response(role, response)
        _validate_response_schema(role, response)
        return response

    def _complete_local_executor(self, prompt: str) -> dict[str, Any]:
        context = _extract_context_json(prompt)
        round_number = int(context.get("round") or 1)
        tool_request = context.get("planner_output", {}).get("tool_request", {})
        tool_id = tool_request.get("tool_id")
        if tool_id != "bash":
            return {
                "status": "failed",
                "artifact": None,
                "summary": f"Local executor does not support tool_id {tool_id!r}.",
                "failure_reason": f"unsupported local executor tool_id: {tool_id}",
                "observations": [],
            }
        arguments = tool_request.get("arguments") or {}
        command = arguments.get("command")
        if not isinstance(command, str) or not command:
            return {
                "status": "failed",
                "artifact": None,
                "summary": "Local executor could not run bash because arguments.command is missing.",
                "failure_reason": "missing local executor bash arguments.command",
                "observations": [],
            }

        workspace = Path(self.cwd) if self.cwd is not None else Path.cwd()
        relative_artifact = f"findings/local_executor_round_{round_number}.json"
        artifact_path = workspace / relative_artifact
        artifact_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            completed = subprocess.run(
                ["bash", "-lc", command],
                cwd=self.cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            result = {
                "command": command,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        except subprocess.TimeoutExpired as exc:
            result = {
                "command": command,
                "returncode": None,
                "stdout": _coerce_process_text(exc.stdout),
                "stderr": _coerce_process_text(exc.stderr),
            }
            artifact_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return {
                "status": "failed",
                "artifact": relative_artifact,
                "summary": f"Local executor bash command timed out after {exc.timeout} seconds.",
                "failure_reason": f"local executor timeout after {exc.timeout} seconds",
                "observations": [],
            }

        artifact_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        status = "completed" if completed.returncode == 0 else "failed"
        failure_reason = None if completed.returncode == 0 else f"bash exited with code {completed.returncode}"
        return {
            "status": status,
            "artifact": relative_artifact,
            "summary": f"Local executor ran bash command with exit code {completed.returncode}.",
            "failure_reason": failure_reason,
            "observations": [
                f"exit code {completed.returncode}",
                f"stdout bytes {len(completed.stdout)}",
                f"stderr bytes {len(completed.stderr)}",
            ],
        }


def load_ai_config(path: Path | str) -> AIConfig:
    data = _load_yaml_minimal(Path(path))
    workers = []
    task_types_by_name = {}
    for raw_worker in data.get("workers", []):
        if not isinstance(raw_worker, dict):
            continue
        name = str(raw_worker.get("name", "")).strip()
        if not name:
            continue
        backend_type = _normalize_backend_type(str(raw_worker.get("type", name)))
        raw_env = raw_worker.get("env") or {}
        env = {str(key): str(value) for key, value in raw_env.items() if value is not None}
        workers.append(AIBackendConfig(name=name, backend_type=backend_type, env=env))
        task_types_by_name[name] = tuple(str(item) for item in (raw_worker.get("task_types") or []))
    return AIConfig(workers=tuple(workers), task_types=task_types_by_name)


def parse_ai_stdout(stdout: str) -> dict[str, Any]:
    text = stdout.strip()
    if not text:
        raise RuntimeError("AI backend returned empty stdout")
    parsed = _parse_json_object_from_text(text)
    if parsed is not None:
        return parsed
    raise RuntimeError(f"AI backend stdout did not contain a JSON object; stdout summary: {_safe_stdout_summary(stdout)}")


def _parse_json_object_from_text(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return _unwrap_cli_envelope(data) or data
    except json.JSONDecodeError:
        pass

    for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL):
        try:
            data = json.loads(match.group(1).strip())
            if isinstance(data, dict):
                return _unwrap_cli_envelope(data) or data
        except json.JSONDecodeError:
            continue

    objects: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            data, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            objects.append(data)
    if objects:
        return _unwrap_cli_envelope(objects[-1]) or objects[-1]
    return None


def _unwrap_cli_envelope(data: dict[str, Any]) -> dict[str, Any] | None:
    for field in CLI_ENVELOPE_TEXT_FIELDS:
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        parsed = _parse_json_object_from_text(value.strip())
        if parsed is not None:
            return parsed
    return None


def _command_for_backend(backend: str, prompt: str) -> list[str]:
    backend_type = _normalize_backend_type(backend)
    if backend_type == "codex":
        return ["codex", "exec", "--json", prompt]
    if backend_type == "claude":
        return ["claude", "-p", "--output-format", "json", prompt]
    raise ValueError(f"unsupported AI backend: {backend}")


def _normalize_backend_type(backend: str) -> str:
    normalized = backend.strip().lower()
    if normalized in {"claude", "claude-code", "claudecode"}:
        return "claude"
    if normalized == "codex":
        return "codex"
    return normalized


def _merged_env(extra: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(extra)
    return env


def _coerce_process_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _write_ai_debug_artifact(
    *,
    cwd: str | None,
    backend: str,
    role: str,
    round_number: int,
    returncode: int | None,
    stdout: str,
    stderr: str,
) -> None:
    workspace = Path(cwd) if cwd is not None else Path.cwd()
    artifact_path = workspace / "findings" / f"ai_{role}_round_{round_number}.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "backend": backend,
        "role": role,
        "round": round_number,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }
    artifact_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _normalize_response(role: str, response: dict[str, Any]) -> dict[str, Any]:
    if role != "verifier":
        return response

    normalized = dict(response)
    if "facts" not in normalized and isinstance(normalized.get("verified_facts"), list):
        normalized["facts"] = normalized["verified_facts"]
    if "new_hypotheses" not in normalized and isinstance(normalized.get("hypotheses"), list):
        normalized["new_hypotheses"] = normalized["hypotheses"]

    for field in ("facts", "rejected", "pending", "new_hypotheses"):
        if field not in normalized:
            normalized[field] = []
    if "value" not in normalized:
        normalized["value"] = {"level": "information leak", "reason": "verifier omitted value"}
    return normalized


def _validate_response_schema(role: str, response: dict[str, Any]) -> None:
    for field in REQUIRED_RESPONSE_FIELDS[role]:
        if field not in response:
            keys = ", ".join(sorted(str(key) for key in response)) or "(none)"
            raise RuntimeError(f"{role} response missing required field: {field}; response keys: {keys}")


def _validate_role(role: str) -> None:
    if role not in VALID_ROLES:
        raise ValueError(f"invalid AI loop role: {role}")


def _safe_stdout_summary(stdout: str, limit: int = 500) -> str:
    summary = stdout.strip().replace("\r", "\\r").replace("\n", "\\n")
    summary = re.sub(
        r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|AUTH)[A-Z0-9_]*\s*=\s*)([^\s\\]+)",
        r"\1<redacted>",
        summary,
    )
    if len(summary) > limit:
        return f"{summary[:limit]}..."
    return summary


def _extract_round(prompt: str) -> int:
    try:
        context = _extract_context_json(prompt)
        return int(context.get("round") or 1)
    except (json.JSONDecodeError, RuntimeError, TypeError, ValueError):
        return 1


def _extract_context_json(prompt: str) -> dict[str, Any]:
    marker = "Context JSON:"
    if marker not in prompt:
        raise RuntimeError("prompt does not contain Context JSON")
    json_text = prompt.split(marker, 1)[1].strip()
    context, _ = json.JSONDecoder().raw_decode(json_text)
    if not isinstance(context, dict):
        raise RuntimeError("Context JSON must be an object")
    return context


def _load_yaml_minimal(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return _parse_dispatch_yaml_subset(path.read_text(encoding="utf-8"))

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"AI config {path} must be a YAML mapping")
    return data


def _parse_dispatch_yaml_subset(text: str) -> dict[str, Any]:
    workers: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_env: dict[str, str] | None = None
    current_list_key: str | None = None
    in_workers = False

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_workers = stripped == "workers:"
            current = None
            current_env = None
            current_list_key = None
            continue
        if not in_workers:
            continue
        if indent == 2 and stripped.startswith("- "):
            current = {}
            workers.append(current)
            current_env = None
            current_list_key = None
            remainder = stripped[2:].strip()
            if remainder:
                key, value = _split_yaml_key_value(remainder)
                current[key] = value
            continue
        if current is None:
            continue
        if indent == 4 and stripped.endswith(":"):
            key = stripped[:-1]
            if key == "env":
                current_env = {}
                current["env"] = current_env
                current_list_key = None
            else:
                current[key] = []
                current_list_key = key
                current_env = None
            continue
        if indent == 4 and ":" in stripped:
            key, value = _split_yaml_key_value(stripped)
            current[key] = value
            current_env = None
            current_list_key = None
            continue
        if indent == 6 and stripped.startswith("- ") and current_list_key:
            current[current_list_key].append(_unquote_yaml_scalar(stripped[2:].strip()))
            continue
        if indent == 6 and current_env is not None and ":" in stripped:
            key, value = _split_yaml_key_value(stripped)
            current_env[key] = value

    return {"workers": workers}


def _split_yaml_key_value(text: str) -> tuple[str, str]:
    key, value = text.split(":", 1)
    return key.strip(), _unquote_yaml_scalar(value.strip())


def _unquote_yaml_scalar(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
