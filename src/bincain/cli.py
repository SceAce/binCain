from __future__ import annotations

import click

from bincain.init import init_challenge
from bincain.repro import generate_repro
from bincain.triage import write_crash_report


@click.group()
def main() -> None:
    """binCain worker helper commands."""


@click.command(name="init")
@click.argument("target", type=click.Path(exists=True, path_type=str))
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
def init_cmd(target: str, workspace: str) -> None:
    """Normalize challenge artifacts."""
    result = init_challenge(target, workspace)
    click.echo(json_dump(result))


@click.command(name="triage")
@click.option("--binary", "binary", required=True)
@click.option("--input", "crash_input", type=click.Path(exists=True, path_type=str), required=True)
@click.option("--output", "output", type=click.Path(path_type=str), required=True)
@click.option("--arch", default="unknown", show_default=True)
@click.option("--signal", "signal_name", default=None)
def triage_cmd(binary: str, crash_input: str, output: str, arch: str, signal_name: str | None) -> None:
    """Build a compact crash triage report."""
    result = write_crash_report(
        output=output,
        binary=binary,
        crash_input=crash_input,
        arch=arch,
        signal=signal_name,
    )
    click.echo(json_dump(result))


@click.command(name="repro")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--crash-report", type=click.Path(exists=True, path_type=str), required=True)
@click.option("--profile", default="raw", show_default=True)
def repro_cmd(workspace: str, crash_report: str, profile: str) -> None:
    """Generate a replay script from a crash report."""
    result = generate_repro(workspace=workspace, crash_report=crash_report, profile=profile)
    click.echo(json_dump(result))


main.add_command(init_cmd)
main.add_command(triage_cmd)
main.add_command(repro_cmd)


def json_dump(value: object) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True)
