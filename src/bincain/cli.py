from __future__ import annotations

import click

from bincain.init import init_challenge


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
def triage_cmd() -> None:
    """Build a compact crash triage report."""
    raise click.ClickException("binCain-triage is not implemented yet")


main.add_command(init_cmd)
main.add_command(triage_cmd)


def json_dump(value: object) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True)
