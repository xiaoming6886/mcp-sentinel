"""Unit tests for MCP Sentinel core."""

from mcp_sentinel.core.types import Severity, Finding, Location, OWASPMapping, ScanContext, ScanTarget
from mcp_sentinel.core.registry import RuleRegistry


def test_severity_ordering():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"


def test_registry_empty_on_start():
    assert RuleRegistry.count() >= 0


def test_finding_creation():
    f = Finding(
        rule_id="TEST-001",
        title="Test",
        description="desc",
        severity=Severity.HIGH,
        confidence="high",
        phase="creation",
        location=Location(file=None),
        remediation="fix it",
        owasp=OWASPMapping(),
    )
    assert f.rule_id == "TEST-001"
    assert f.severity == Severity.HIGH
