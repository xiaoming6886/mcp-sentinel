"""Integration tests for MCP Sentinel CLI."""

from typer.testing import CliRunner
from mcp_sentinel.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "MCP Sentinel" in result.stdout


def test_list_rules():
    result = runner.invoke(app, ["list-rules"])
    assert result.exit_code == 0


def test_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
