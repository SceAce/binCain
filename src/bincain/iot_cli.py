from __future__ import annotations

import json

import click

from bincain.asset import ingest_seed
from bincain.iot_loop import run_iot_loop


@click.command(name="loop")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--rounds", default=3, show_default=True)
@click.option("--ai-provider", type=click.Choice(["mock", "agent"]), default="mock", show_default=True)
@click.option("--planner", default="codex", show_default=True)
@click.option("--executor", default="codex", show_default=True)
@click.option("--verifier", default="claude", show_default=True)
def loop_cmd(workspace: str, rounds: int, ai_provider: str, planner: str, executor: str, verifier: str) -> None:
    """Run the autonomous IoT graph loop."""
    result = run_iot_loop(
        workspace=workspace,
        rounds=rounds,
        ai_provider=ai_provider,
        planner=planner,
        executor=executor,
        verifier=verifier,
    )
    click.echo(json.dumps(result, indent=2, sort_keys=True))


@click.group(name="asset")
def asset_cmd() -> None:
    """Manage IoT asset seeds."""


@asset_cmd.command(name="ingest")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--seed", type=click.Path(exists=True, path_type=str), required=True)
def asset_ingest_cmd(workspace: str, seed: str) -> None:
    """Ingest an IoT asset seed JSON file."""
    click.echo(json.dumps(ingest_seed(workspace=workspace, seed=seed), indent=2, sort_keys=True))
