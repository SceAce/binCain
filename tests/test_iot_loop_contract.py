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
