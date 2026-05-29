from __future__ import annotations

import click

from bincain.init import init_challenge
from bincain.primitive import assert_leak, assert_offset, assert_pc, assert_write
from bincain.protocol import generate_protocol_template
from bincain.repro import generate_repro
from bincain.triage import run_gdb_triage, write_crash_report


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
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--gdb/--no-gdb", "use_gdb", default=False, show_default=True)
@click.option("--gdb-bin", default=None)
@click.option("--timeout", default=10, show_default=True)
def triage_cmd(
    binary: str,
    crash_input: str,
    output: str,
    arch: str,
    signal_name: str | None,
    workspace: str,
    use_gdb: bool,
    gdb_bin: str | None,
    timeout: int,
) -> None:
    """Build a compact crash triage report."""
    if use_gdb:
        result = run_gdb_triage(
            binary=binary,
            crash_input=crash_input,
            output=output,
            workspace=workspace,
            arch=arch,
            gdb=gdb_bin,
            timeout=timeout,
        )
    else:
        result = write_crash_report(
            output=output,
            binary=binary,
            crash_input=crash_input,
            arch=arch,
            signal=signal_name,
            workspace=workspace,
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


@click.command(name="protocol-template")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--topology", type=click.Path(exists=True, path_type=str), required=True)
def protocol_template_cmd(workspace: str, topology: str) -> None:
    """Generate a base interaction template from menu topology JSON."""
    import json

    with open(topology, encoding="utf-8") as handle:
        data = json.load(handle)
    result = generate_protocol_template(workspace, data)
    click.echo(json_dump(result))


@click.group(name="primitive")
def primitive_cmd() -> None:
    """Assert primitive proof candidates."""


@primitive_cmd.command(name="assert-pc")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--crash", "crash_report", type=click.Path(exists=True, path_type=str), required=True)
def primitive_assert_pc_cmd(workspace: str, crash_report: str) -> None:
    click.echo(json_dump(assert_pc(workspace=workspace, crash_report=crash_report)))


@primitive_cmd.command(name="assert-offset")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--crash", "crash_report", type=click.Path(exists=True, path_type=str), required=True)
def primitive_assert_offset_cmd(workspace: str, crash_report: str) -> None:
    click.echo(json_dump(assert_offset(workspace=workspace, crash_report=crash_report)))


@primitive_cmd.command(name="assert-leak")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--candidate", "candidates", multiple=True, required=True)
@click.option("--maps", "maps_file", type=click.Path(exists=True, path_type=str), default=None)
@click.option("--repro", "reproducer", default=None)
def primitive_assert_leak_cmd(
    workspace: str,
    candidates: tuple[str, ...],
    maps_file: str | None,
    reproducer: str | None,
) -> None:
    click.echo(json_dump(assert_leak(workspace=workspace, candidates=list(candidates), maps_file=maps_file, reproducer=reproducer)))


@primitive_cmd.command(name="assert-write")
@click.option("--workspace", type=click.Path(path_type=str), default="/home/kali/workspace", show_default=True)
@click.option("--target", default="unknown", show_default=True)
@click.option("--repro", "reproducer", default=None)
@click.option("--watch", default=None)
@click.option("--verified/--unverified", default=False, show_default=True)
def primitive_assert_write_cmd(workspace: str, target: str, reproducer: str | None, watch: str | None, verified: bool) -> None:
    click.echo(json_dump(assert_write(workspace=workspace, target=target, reproducer=reproducer, watch=watch, verified=verified)))


main.add_command(init_cmd)
main.add_command(triage_cmd)
main.add_command(repro_cmd)
main.add_command(protocol_template_cmd)
main.add_command(primitive_cmd)


def json_dump(value: object) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True)
