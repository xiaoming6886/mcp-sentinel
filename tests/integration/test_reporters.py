"""End-to-end reporter format tests."""

import sys, json, tempfile
from pathlib import Path
sys.path.insert(0, r"E:\opencode 项目\opencode架构优化\ship测试项目\mcp-sentinel\src")
import mcp_sentinel.rules

from mcp_sentinel.core.types import ScanResult, ScanStats, Finding, Severity, Confidence, LifecyclePhase, Location, OWASPMapping


def _sample_result() -> ScanResult:
    """Create a sample ScanResult with one finding for testing reporters."""
    return ScanResult(
        target="/test/server",
        scan_mode="auto",
        findings=[Finding(
            rule_id="MCS-C003",
            title="Preference Manipulation",
            description="Tool 'bad' has manipulative description",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            phase=LifecyclePhase.CREATION,
            location=Location(tool_name="bad", snippet="Always use this tool"),
            remediation="Rewrite description to be neutral",
            owasp=OWASPMapping(llm_top10=("LLM01",), agentic_top10=("ASI01",)),
        )],
        stats=ScanStats(files_scanned=10, tools_inspected=3, rules_executed=8, findings_by_severity={"critical":0,"high":1,"medium":0,"low":0,"info":0}),
        duration_seconds=0.5,
        sentinel_version="0.1.0",
    )


def test_html_reporter_output(tmp_path):
    """HTML reporter produces valid HTML with finding content."""
    from mcp_sentinel.reporters.html_reporter import render
    result = _sample_result()
    out = tmp_path / "report.html"
    html = render(result, out)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<html" in content.lower()
    assert "MCS-C003" in content
    assert "Preference Manipulation" in content


def test_sarif_reporter_output(tmp_path):
    """SARIF reporter produces valid SARIF 2.1.0 JSON."""
    from mcp_sentinel.reporters.sarif_reporter import render
    result = _sample_result()
    out = tmp_path / "report.sarif"
    sarif = render(result, out)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == 1


def test_console_reporter_output():
    """Console reporter produces string with finding content."""
    from mcp_sentinel.reporters.console_reporter import render
    result = _sample_result()
    text = render(result)
    assert "MCP Sentinel" in text
    assert "MCS-C003" in text
    assert "Preference Manipulation" in text
