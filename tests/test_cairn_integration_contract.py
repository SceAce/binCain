from pathlib import Path


PROMPT_DIR = Path("integration/cairn/prompts/pwn")


def test_pwn_prompt_group_contains_required_files_and_placeholders():
    required = {
        "bootstrap.md": ["{origin}", "{goal}", "{hints}"],
        "bootstrap_conclude.md": ["{origin}", "{goal}", "{hints}"],
        "reason.md": ["{graph_yaml}", "{fact_ids}", "{open_intents}"],
        "explore.md": ["{graph_yaml}", "{intent_id}", "{intent_description}"],
        "explore_conclude.md": ["{graph_yaml}", "{intent_id}", "{intent_description}"],
    }

    for name, placeholders in required.items():
        text = (PROMPT_DIR / name).read_text()
        for placeholder in placeholders:
            assert placeholder in text
        assert '"accepted"' in text
        assert "Fact.description" in text


def test_dispatch_profile_selects_pwn_prompts_and_worker_image():
    text = Path("integration/cairn/dispatch.pwn.yaml").read_text()

    assert 'prompt_group: "pwn"' in text
    assert "image: bincain-worker:" in text
    assert "completed_action: stop" in text
    assert "task_types: [bootstrap, reason, explore]" in text


def test_prompt_sync_script_documents_cairn_package_target():
    text = Path("scripts/sync_cairn_prompts.sh").read_text()

    assert "integration/cairn/prompts/pwn" in text
    assert "cairn/src/cairn/dispatcher/prompts/pwn" in text
