import json
from pathlib import Path

from bincain.artifacts import append_event, create_summary_snapshot, read_latest_summary, update_summary


def test_append_event_allocates_sequence_and_writes_jsonl(tmp_path: Path):
    workspace = tmp_path / "workspace"

    first = append_event(workspace, source="binCain-init", kind="initialized", summary="baseline ready")
    second = append_event(
        workspace,
        source="binCain-triage",
        kind="crash_triaged",
        summary="crash ready",
        artifact="findings/crash_000001.json",
    )

    events = (workspace / "findings" / "events.jsonl").read_text().splitlines()
    assert first["seq"] == 1
    assert second["seq"] == 2
    assert json.loads(events[0])["kind"] == "initialized"
    assert json.loads(events[1])["artifact"] == "findings/crash_000001.json"


def test_update_summary_writes_latest_atomically_and_snapshot(tmp_path: Path):
    workspace = tmp_path / "workspace"
    event = append_event(workspace, source="binCain-init", kind="initialized", summary="baseline ready")

    summary = update_summary(
        workspace,
        target={"path": "target/chall"},
        run_profiles={"default": "raw"},
        selected_crashes=[{"id": "crash_000001", "summary": "rip control"}],
    )
    snapshot = create_summary_snapshot(workspace, summary)

    latest = read_latest_summary(workspace)
    assert latest["latest_event_seq"] == event["seq"]
    assert latest["target"]["path"] == "target/chall"
    assert latest["selected_crashes"][0]["id"] == "crash_000001"
    assert snapshot.name == "summary_000001.json"
    assert json.loads(snapshot.read_text())["latest_event_seq"] == 1
