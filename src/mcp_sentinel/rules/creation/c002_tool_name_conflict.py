"""MCS-C002: Tool Name Conflict Detection.

Scans multi-server manifests for duplicate tool names that could cause
ambiguous tool resolution at runtime.
"""

from __future__ import annotations

from collections import Counter

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


@register_rule("MCS-C002", LifecyclePhase.CREATION, Severity.MEDIUM, "Tool Name Conflict")
class ToolNameConflictRule(BaseRule):
    """Flag duplicate tool names that appear in two or more server manifests."""

    requires_manifest = True

    def check(self, ctx: ScanContext) -> list:
        findings: list = []

        manifests = ctx.manifests
        if not manifests or len(manifests) < 2:
            return findings

        # Collect all (tool_name, server_name) pairs
        tool_entries: list[tuple[str, str]] = []
        for manifest in manifests:
            for tool in manifest.tools:
                if tool.name:
                    tool_entries.append((tool.name, manifest.server_name or "<unknown>"))

        # Find tool names that appear in 2+ distinct servers
        name_counts: Counter[str] = Counter()
        name_to_servers: dict[str, set[str]] = {}
        for tool_name, server_name in tool_entries:
            name_counts[tool_name] += 1
            name_to_servers.setdefault(tool_name, set()).add(server_name)

        reported: set[str] = set()
        for tool_name, servers in name_to_servers.items():
            if len(servers) >= 2 and tool_name not in reported:
                reported.add(tool_name)
                server_list = ", ".join(sorted(servers))
                findings.append(
                    self._make_finding(
                        description=(
                            f"Tool name '{tool_name}' is defined in {len(servers)} "
                            f"different servers: {server_list}. "
                            f"This may cause ambiguous tool resolution."
                        ),
                        location=Location(
                            tool_name=tool_name,
                            snippet=f"tool: {tool_name} → servers: {server_list}",
                        ),
                        remediation=(
                            f"Rename conflicting tool(s) or use server-qualified names "
                            f"(e.g., '{servers.pop()}_{tool_name}'). "
                            f"Ensure each tool name is unique across all connected MCP servers."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI02",),
                        ),
                        confidence=Confidence.HIGH,
                    )
                )

        return findings
