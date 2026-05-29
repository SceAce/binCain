from pathlib import Path


def test_worker_agents_mentions_primitives_and_angr_guardrail():
    text = Path("worker/AGENTS.md").read_text()

    assert "Level 1" in text
    assert "Level 2" in text
    assert "Level 3" in text
    assert "Do not invoke angr in the first triage round" in text


def test_menu_action_fuzzer_template_has_mutation_entrypoint():
    text = Path("worker/templates/menu_action_fuzzer.py").read_text()

    assert "def mutate_actions" in text
    assert "def run_case" in text


def test_worker_docs_describe_run_profiles_events_and_falsifiable_intents():
    text = Path("worker/AGENTS.md").read_text()

    assert "run_target.sh --profile" in text
    assert "events.jsonl" in text
    assert "summary_latest.json" in text
    assert "falsifiable" in text.lower()
    assert "binCain-primitive" in text
