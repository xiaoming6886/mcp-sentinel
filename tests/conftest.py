"""Shared pytest fixtures for MCP Sentinel tests."""

import pytest
from pathlib import Path
from mcp_sentinel.core.types import (
    ScanContext, ScanTarget, MCPManifest, ToolDef, Severity, Finding, Location
)

# Exclude fixture directories from test collection
collect_ignore = ["fixtures"]


@pytest.fixture
def sample_tool() -> ToolDef:
    return ToolDef(name="read_file", description="Read a file from disk", server_name="test-server")


@pytest.fixture
def sample_manifest(sample_tool) -> MCPManifest:
    return MCPManifest(server_name="test-server", server_version="1.0.0", tools=[sample_tool])


@pytest.fixture
def sample_target(tmp_path: Path) -> ScanTarget:
    return ScanTarget(path=str(tmp_path), mode="auto")


@pytest.fixture
def sample_context(sample_target, sample_manifest) -> ScanContext:
    return ScanContext(target=sample_target, manifest=sample_manifest)
