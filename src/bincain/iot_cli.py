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
@click.option("--allow-real-ai", is_flag=True, help="Allow the agent provider to invoke real AI CLI backends.")
@click.option("--ai-config", type=click.Path(exists=True, path_type=str), default=None, help="Dispatch-style AI worker config.")
@click.option("--planner-backend", default=None, help="Planner worker name or backend type.")
@click.option("--executor-backend", default=None, help="Executor worker name or backend type.")
@click.option("--verifier-backend", default=None, help="Verifier worker name or backend type.")
@click.option("--ai-timeout", type=int, default=None, help="Timeout in seconds for each AI CLI call.")
def loop_cmd(
    workspace: str,
    rounds: int,
    ai_provider: str,
    planner: str,
    executor: str,
    verifier: str,
    allow_real_ai: bool,
    ai_config: str | None,
    planner_backend: str | None,
    executor_backend: str | None,
    verifier_backend: str | None,
    ai_timeout: int | None,
) -> None:
    """Run the autonomous IoT graph loop."""
    result = run_iot_loop(
        workspace=workspace,
        rounds=rounds,
        ai_provider=ai_provider,
        planner=planner,
        executor=executor,
        verifier=verifier,
        allow_real_ai=allow_real_ai,
        ai_config=ai_config,
        planner_backend=planner_backend,
        executor_backend=executor_backend,
        verifier_backend=verifier_backend,
        ai_timeout=ai_timeout,
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
