from pathlib import Path

from bincain.ai_loop import render_prompt


def test_iot_loop_prompts_exist_and_define_json_outputs():
    for role in ["planner", "executor", "verifier"]:
        text = render_prompt(role, {"round": 1})
        assert "JSON" in text
        assert "Fact" in text or "已知事实" in text
        assert "Intent" in text or "待验证" in text
        assert '"round": 1' in text


def test_worker_dockerfile_checks_iot_loop_commands():
    text = Path("worker/Dockerfile").read_text()
    assert "binCain-loop --help" in text
    assert "binCain-asset --help" in text
