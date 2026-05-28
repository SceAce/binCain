from bincain import __version__
from bincain.cli import main


def test_package_exposes_version_and_cli_group():
    assert isinstance(__version__, str)
    assert __version__
    assert callable(main)
