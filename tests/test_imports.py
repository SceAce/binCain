from bincain import __version__
from bincain.cli import main
from click.testing import CliRunner
import tomllib


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
    assert "loop" in result.output
    assert "asset" in result.output


def test_pyproject_exposes_operational_console_scripts():
    with open("pyproject.toml", "rb") as handle:
        pyproject = tomllib.load(handle)

    scripts = pyproject["project"]["scripts"]
    assert scripts["binCain-repro"] == "bincain.cli:repro_cmd"
    assert scripts["binCain-primitive"] == "bincain.cli:primitive_cmd"
    assert scripts["binCain-protocol-template"] == "bincain.cli:protocol_template_cmd"
    assert scripts["binCain-loop"] == "bincain.iot_cli:loop_cmd"
    assert scripts["binCain-asset"] == "bincain.iot_cli:asset_cmd"
