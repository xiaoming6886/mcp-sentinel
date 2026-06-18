"""MCS-C003: Preference Manipulation Detection.

Scans tool descriptions for manipulative language patterns designed to
influence an LLM's tool selection behavior (e.g., "always use this tool",
"prefer me over others").
"""

from __future__ import annotations

import re

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule


# Patterns that indicate attempts to manipulate LLM tool selection
_MANIPULATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"always\s+use\s+(this\s+)?(tool|function|method)", re.IGNORECASE),
    re.compile(r"prefer\s+(me|this\s+tool)\s+over", re.IGNORECASE),
    re.compile(r"only\s+(tool|function|method)\s+(you\s+should\s+)?(use|call|invoke)", re.IGNORECASE),
    re.compile(r"ignore\s+(other|all\s+other)\s+(tools|functions|methods)", re.IGNORECASE),
    re.compile(r"you\s+must\s+(use|call|invoke)\s+(this\s+)?(tool|me)", re.IGNORECASE),
    re.compile(r"this\s+is\s+the\s+(only|best|correct|recommended)\s+(tool|choice|option)", re.IGNORECASE),
    re.compile(r"do\s+not\s+use\s+(any\s+)?(other|alternative)\s+(tool|function|method)", re.IGNORECASE),
    re.compile(r"supersedes?\s+(all\s+)?(other\s+)?(tools|functions|methods)", re.IGNORECASE),
    re.compile(r"designated\s+(primary|default|preferred)\s+(tool|function)", re.IGNORECASE),
    re.compile(r"highest?\s+priority\s+(tool|function|method)", re.IGNORECASE),
]

_MIN_MATCHES = 1


@register_rule("MCS-C003", LifecyclePhase.CREATION, Severity.HIGH, "Preference Manipulation")
class PreferenceManipulationRule(BaseRule):
    """Flag tool descriptions that contain patterns designed to manipulate LLM behavior."""

    requires_manifest = True

    def _scan_description(self, description: str) -> list[re.Pattern]:
        """Return list of patterns that matched the description."""
        if not description:
            return []
        matched: list[re.Pattern] = []
        for pattern in _MANIPULATION_PATTERNS:
            if pattern.search(description):
                matched.append(pattern)
        return matched

    def check(self, ctx: ScanContext) -> list:
        findings: list = []

        manifest = ctx.manifest
        if manifest is None:
            return findings

        for tool in manifest.tools:
            if not tool.description:
                continue

            matches = self._scan_description(tool.description)
            if len(matches) >= _MIN_MATCHES:
                snippet = tool.description[:200]
                findings.append(
                    self._make_finding(
                        description=(
                            f"Tool '{tool.name}' contains {len(matches)} manipulative language "
                            f"patterns in its description, suggesting an attempt to bias LLM "
                            f"tool selection. Patterns: {', '.join(m.pattern for m in matches)}"
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=snippet,
                        ),
                        remediation=(
                            f"Rewrite the description for tool '{tool.name}' to be factual "
                            f"and neutral. Remove any language that instructs or pressures the "
                            f"LLM to select this tool over others. Descriptions should describe "
                            f"capability, not preference."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                    )
                )

        return findings
