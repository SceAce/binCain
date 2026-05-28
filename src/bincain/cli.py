from __future__ import annotations

import click


@click.group()
def main() -> None:
    """binCain worker helper commands."""


@click.command(name="init")
def init_cmd() -> None:
    """Normalize challenge artifacts."""
    raise click.ClickException("binCain-init is not implemented yet")


@click.command(name="triage")
def triage_cmd() -> None:
    """Build a compact crash triage report."""
    raise click.ClickException("binCain-triage is not implemented yet")


main.add_command(init_cmd)
main.add_command(triage_cmd)
