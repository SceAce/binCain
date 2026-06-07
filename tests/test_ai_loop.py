import json
import subprocess

import pytest

from bincain.ai_loop import (
    AgentProvider,
    MockAIProvider,
    _normalize_backend_type,
    load_ai_config,
    parse_ai_stdout,
    render_prompt,
)


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


def test_mock_provider_reads_round_from_rendered_prompt():
    prompt = render_prompt(
        "planner",
        {
            "round": 3,
            "summary": {"iot_graph": {"intent_count": 2}},
            "graph": {"facts": [], "intents": [], "hints": []},
            "tool_registry": {"tools": [{"id": "bash"}]},
        },
    )

    plan = MockAIProvider().complete(role="planner", prompt=prompt)

    assert plan["chosen_intent"].endswith("round 3")


def test_mock_provider_returns_structured_outputs():
    provider = MockAIProvider()

    plan = provider.complete(role="planner", prompt='Context JSON:\n{"round": 2}')
    execution = provider.complete(role="executor", prompt='Context JSON:\n{"round": 2}')
    verification = provider.complete(role="verifier", prompt='Context JSON:\n{"round": 2}')

    assert plan["tool_request"]["tool_id"] == "bash"
    assert plan["chosen_intent"].endswith("round 2")
    assert execution["artifact"] == "findings/mock_executor_round_2.json"
    assert verification["facts"]
    assert "round 2" in verification["facts"][0]["description"]


def test_agent_provider_requires_authenticated_backend():
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=False)

    with pytest.raises(RuntimeError, match="--allow-real-ai"):
        provider.complete(role="planner", prompt="hello")


def test_local_executor_backend_runs_bash_and_writes_artifact(tmp_path):
    prompt = render_prompt(
        "executor",
        {
            "round": 4,
            "planner_output": {
                "tool_request": {
                    "tool_id": "bash",
                    "arguments": {"command": "printf local-ok"},
                }
            },
        },
    )
    provider = AgentProvider(executor="local", cwd=tmp_path, timeout=5)

    response = provider.complete(role="executor", prompt=prompt)

    assert response["status"] == "completed"
    assert response["artifact"] == "findings/local_executor_round_4.json"
    assert response["failure_reason"] is None
    assert response["observations"] == ["exit code 0", "stdout bytes 8", "stderr bytes 0"]
    artifact = tmp_path / response["artifact"]
    assert artifact.exists()
    data = json.loads(artifact.read_text(encoding="utf-8"))
    assert data == {"command": "printf local-ok", "returncode": 0, "stderr": "", "stdout": "local-ok"}


def test_local_executor_backend_reports_unsupported_tool(tmp_path):
    prompt = render_prompt(
        "executor",
        {
            "round": 2,
            "planner_output": {
                "tool_request": {
                    "tool_id": "python",
                    "arguments": {"command": "print('nope')"},
                }
            },
        },
    )
    provider = AgentProvider(executor="local", cwd=tmp_path)

    response = provider.complete(role="executor", prompt=prompt)

    assert response["status"] == "failed"
    assert response["artifact"] is None
    assert "unsupported local executor tool_id: python" == response["failure_reason"]
    assert response["observations"] == []


def test_load_ai_config_maps_workers_by_task_type_and_name(tmp_path):
    config = tmp_path / "dispatch.yaml"
    config.write_text(
        """
workers:
  - name: thinker-claude
    type: claudecode
    task_types:
      - planner
      - verifier
    env:
      ANTHROPIC_MODEL: claude-opus-4
      ANTHROPIC_BASE_URL: https://example.invalid
      ANTHROPIC_AUTH_TOKEN: secret-token
  - name: doer-codex
    type: codex
    task_types:
      - executor
    env:
      ANTHROPIC_MODEL: deepseek-v4
""",
        encoding="utf-8",
    )

    ai_config = load_ai_config(config)
    backends = ai_config.resolve_backends(
        planner_backend=None,
        executor_backend="doer-codex",
        verifier_backend=None,
    )

    assert backends["planner"].name == "thinker-claude"
    assert backends["planner"].backend_type == "claude"
    assert backends["executor"].name == "doer-codex"
    assert backends["executor"].backend_type == "codex"
    assert backends["verifier"].env["ANTHROPIC_MODEL"] == "claude-opus-4"
    assert "secret-token" not in repr(backends["planner"])


def test_load_ai_config_normalizes_local_backend(tmp_path):
    config = tmp_path / "dispatch.yaml"
    config.write_text(
        """
workers:
  - name: local
    type: local
    task_types:
      - executor
""",
        encoding="utf-8",
    )

    ai_config = load_ai_config(config)

    assert _normalize_backend_type("local") == "local"
    assert ai_config.resolve_backend("executor", "local").backend_type == "local"


def test_parse_ai_stdout_accepts_pure_fenced_and_jsonl_objects():
    assert parse_ai_stdout('{"status": "completed"}') == {"status": "completed"}
    assert parse_ai_stdout('```json\n{"facts": []}\n```') == {"facts": []}
    assert parse_ai_stdout('log line\n{"partial": true}\n{"final": true}') == {"final": True}


def test_parse_ai_stdout_extracts_json_from_cli_envelope_result():
    assert parse_ai_stdout('{"result": "{\\"facts\\": [], \\"value\\": {\\"level\\": \\"x\\"}}"}') == {
        "facts": [],
        "value": {"level": "x"},
    }


def test_parse_ai_stdout_failure_includes_sanitized_stdout_summary():
    stdout = "debug ANTHROPIC_AUTH_TOKEN=secret-token\nno structured response"

    with pytest.raises(RuntimeError) as exc_info:
        parse_ai_stdout(stdout)

    message = str(exc_info.value)
    assert "stdout summary:" in message
    assert "no structured response" in message
    assert "secret-token" not in message
    assert "ANTHROPIC_AUTH_TOKEN=<redacted>" in message


def test_agent_provider_validates_role_schema(monkeypatch, tmp_path):
    class Completed:
        returncode = 0
        stdout = '{"reason": "missing chosen_intent"}'
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)

    with pytest.raises(RuntimeError) as exc_info:
        provider.complete(role="planner", prompt="hello")

    message = str(exc_info.value)
    assert "planner response missing required field: chosen_intent" in message
    assert "response keys: reason" in message


def test_agent_provider_writes_raw_debug_artifact_for_real_ai(monkeypatch, tmp_path):
    class Completed:
        returncode = 0
        stdout = '{"chosen_intent": "x", "reason": "y", "tool_request": {}}'
        stderr = "debug stderr"

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)
    prompt = render_prompt(
        "planner",
        {
            "round": 6,
            "summary": {},
            "graph": {"facts": [], "intents": [], "hints": []},
            "tool_registry": {"tools": []},
        },
    )

    provider.complete(role="planner", prompt=prompt)

    artifact = tmp_path / "findings" / "ai_planner_round_6.json"
    data = json.loads(artifact.read_text(encoding="utf-8"))
    assert data == {
        "backend": "codex",
        "role": "planner",
        "round": 6,
        "returncode": 0,
        "stdout": Completed.stdout,
        "stderr": "debug stderr",
    }
    assert "env" not in data


def test_agent_provider_writes_raw_debug_artifact_before_schema_failure(monkeypatch, tmp_path):
    class Completed:
        returncode = 0
        stdout = '{"reason": "missing chosen_intent"}'
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)

    with pytest.raises(RuntimeError):
        provider.complete(role="planner", prompt='Context JSON:\n{"round": 3}')

    artifact = tmp_path / "findings" / "ai_planner_round_3.json"
    data = json.loads(artifact.read_text(encoding="utf-8"))
    assert data["stdout"] == Completed.stdout
    assert data["returncode"] == 0


def test_agent_provider_defaults_common_missing_verifier_fields(monkeypatch, tmp_path):
    class Completed:
        returncode = 0
        stdout = (
            '{"verified_facts": [{"description": "x"}], '
            '"hypotheses": [{"description": "h"}]}'
        )
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)

    response = provider.complete(role="verifier", prompt="hello")

    assert response["facts"] == [{"description": "x"}]
    assert response["new_hypotheses"] == [{"description": "h"}]
    assert response["rejected"] == []
    assert response["pending"] == []
    assert response["value"] == {"level": "information leak", "reason": "verifier omitted value"}


def test_planner_missing_fields_still_fails_with_response_keys(monkeypatch, tmp_path):
    class Completed:
        returncode = 0
        stdout = '{"facts": [], "verified_facts": [], "hypotheses": []}'
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)

    with pytest.raises(RuntimeError) as exc_info:
        provider.complete(role="planner", prompt="hello")

    message = str(exc_info.value)
    assert "planner response missing required field: chosen_intent" in message
    assert "response keys: facts, hypotheses, verified_facts" in message


def test_agent_provider_raises_clear_error_on_nonzero_subprocess(monkeypatch, tmp_path):
    class Completed:
        returncode = 7
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)

    with pytest.raises(RuntimeError, match="AI backend codex failed with exit code 7: boom"):
        provider.complete(role="planner", prompt="hello")


def test_agent_provider_raises_clear_error_on_ai_cli_timeout(monkeypatch, tmp_path):
    prompt = "secret prompt body that should not appear"

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"], output=prompt)

    monkeypatch.setattr("subprocess.run", fake_run)
    provider = AgentProvider(
        planner="codex",
        executor="codex",
        verifier="claude",
        allow_real_ai=True,
        timeout=3,
        cwd=tmp_path,
    )

    with pytest.raises(RuntimeError) as exc_info:
        provider.complete(role="planner", prompt=prompt)

    message = str(exc_info.value)
    assert message == "AI backend codex timed out for role planner after 3 seconds"
    assert prompt not in message


def test_local_executor_timeout_artifact_handles_byte_streams(monkeypatch, tmp_path):
    prompt = render_prompt(
        "executor",
        {
            "round": 4,
            "planner_output": {
                "tool_request": {
                    "tool_id": "bash",
                    "arguments": {"command": "sleep 10"},
                }
            },
        },
    )

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"], output=b"partial", stderr=b"late")

    monkeypatch.setattr("subprocess.run", fake_run)
    provider = AgentProvider(executor="local", timeout=1, cwd=tmp_path)

    response = provider.complete(role="executor", prompt=prompt)
    artifact = json.loads((tmp_path / response["artifact"]).read_text())

    assert response["status"] == "failed"
    assert response["failure_reason"] == "local executor timeout after 1 seconds"
    assert artifact["stdout"] == "partial"
    assert artifact["stderr"] == "late"


def test_agent_provider_passes_timeout_cwd_and_config_env(monkeypatch, tmp_path):
    calls = []

    class Completed:
        returncode = 0
        stdout = '{"chosen_intent": "x", "reason": "y", "tool_request": {}, "expected_evidence": [], "new_hypotheses": []}'
        stderr = ""

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    provider = AgentProvider(
        planner="codex",
        executor="codex",
        verifier="claude",
        allow_real_ai=True,
        timeout=17,
        cwd=tmp_path,
        env_by_role={"planner": {"ANTHROPIC_MODEL": "test-model", "ANTHROPIC_AUTH_TOKEN": "secret-token"}},
    )

    provider.complete(role="planner", prompt="hello")

    assert calls[0][0][0] == ["codex", "exec", "--json", "hello"]
    assert calls[0][1]["timeout"] == 17
    assert calls[0][1]["cwd"] == str(tmp_path)
    assert calls[0][1]["env"]["ANTHROPIC_MODEL"] == "test-model"
    assert calls[0][1]["env"]["ANTHROPIC_AUTH_TOKEN"] == "secret-token"


def test_agent_provider_uses_claude_json_output_format(monkeypatch, tmp_path):
    calls = []

    class Completed:
        returncode = 0
        stdout = (
            '{"result": "{\\"facts\\": [], \\"rejected\\": [], \\"pending\\": [], '
            '\\"new_hypotheses\\": [], \\"value\\": {\\"level\\": \\"x\\", \\"reason\\": \\"y\\"}}"}'
        )
        stderr = ""

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", allow_real_ai=True, cwd=tmp_path)

    provider.complete(role="verifier", prompt="hello")

    assert calls[0][0][0] == ["claude", "-p", "--output-format", "json", "hello"]
