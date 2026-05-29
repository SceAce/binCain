from bincain import __version__
from bincain.cli import main
from click.testing import CliRunner


def test_package_exposes_version_and_cli_group():
    assert isinstance(__version__, str)
    assert __version__
    assert callable(main)


def test_cli_lists_operational_hardening_commands():
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "repro" in result.output
    assert "protocol-template" in result.output
    assert "primitive" in result.output
