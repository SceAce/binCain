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
    provider = AgentProvider(planner="codex", executor="codex", verifier="claude", authenticated=False)

    with pytest.raises(RuntimeError, match="AI provider is not authenticated"):
        provider.complete(role="planner", prompt="hello")
