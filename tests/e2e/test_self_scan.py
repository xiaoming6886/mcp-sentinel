"""E2E test: Scan the MCP Sentinel project itself."""

from pathlib import Path
from mcp_sentinel.core.engine import ScanEngine
from mcp_sentinel.core.types import ScanTarget

PROJECT_ROOT = Path(__file__).parent.parent.parent


def test_scan_self():
    """Verify MCP Sentinel can scan its own source code without crashing."""
    target = ScanTarget(path=str(PROJECT_ROOT / "src"), mode="auto")
    engine = ScanEngine()
    result = engine.run(target)
    assert result.target
    assert result.stats.rules_executed >= 0
    assert result.sentinel_version
