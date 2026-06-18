"""Base rule ABC for MCP Sentinel detection rules."""

from __future__ import annotations
from abc import ABC, abstractmethod
from mcp_sentinel.core.types import (
    Confidence,
    Finding,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)


class BaseRule(ABC):
    """Abstract base class for all MCP Sentinel detection rules.

    Subclasses must:
    1. Set RULE_ID, PHASE, DEFAULT_SEVERITY, TITLE as class attributes
    2. Implement check() method
    """

    RULE_ID: str = ""
    PHASE: LifecyclePhase = LifecyclePhase.CREATION
    DEFAULT_SEVERITY: Severity = Severity.MEDIUM
    TITLE: str = ""

    # "all" = ALL requirements must be met (AND, default)
    # "any" = ANY requirement must be met (OR)
    requirement_mode: str = "all"

    @abstractmethod
    def check(self, ctx: ScanContext) -> list[Finding]:
        """Execute the rule against the scan context and return findings."""
        ...

    @property
    def requires_source(self) -> bool:
        """Does this rule need source code (AST) to run?"""
        return False

    @property
    def requires_manifest(self) -> bool:
        """Does this rule need an MCP manifest (tools/list) to run?"""
        return False

    @property
    def requires_config(self) -> bool:
        """Does this rule need MCP client config to run?"""
        return False

    def _make_finding(
        self,
        description: str,
        location: Location,
        remediation: str,
        owasp: OWASPMapping,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        references: list[str] | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        """Factory method to create a Finding with the rule's metadata."""
        return Finding(
            rule_id=self.RULE_ID,
            title=self.TITLE,
            description=description,
            severity=severity or self.DEFAULT_SEVERITY,
            confidence=confidence,
            phase=self.PHASE,
            location=location,
            remediation=remediation,
            owasp=owasp,
            references=references or [],
            metadata=metadata or {},
        )
