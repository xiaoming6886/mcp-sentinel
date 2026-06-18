"""MCS-R002: Cross-Server Shadowing — detect tools that impersonate or shadow
tools from other MCP servers."""

from __future__ import annotations
import re
from typing import TYPE_CHECKING

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    Finding,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SHADOWING_PHRASES: list[re.Pattern] = [
    re.compile(r"instead\s+of\s+(?:using\s+)?(\S+)", re.IGNORECASE),
    re.compile(r"replace\s+(\S+)\s+with\s+(?:this|me)", re.IGNORECASE),
    re.compile(r"use\s+me\s+instead\s+of\s+(\S+)", re.IGNORECASE),
    re.compile(r"alternative\s+to\s+(\S+)", re.IGNORECASE),
    re.compile(r"drop-in\s+replacement\s+for\s+(\S+)", re.IGNORECASE),
    re.compile(r"better\s+than\s+(\S+)", re.IGNORECASE),
    re.compile(r"same\s+as\s+(\S+)\s+but", re.IGNORECASE),
]


def _extract_shadowed_tool_name(description: str) -> str | None:
    """Try to extract a referenced tool name from a description string."""
    for pattern in SHADOWING_PHRASES:
        m = pattern.search(description)
        if m:
            return m.group(1).strip('"\'')
    return None


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


@register_rule("MCS-R002", LifecyclePhase.RUNTIME, Severity.HIGH, "Cross-Server Shadowing")
class R002CrossServerShadowing(BaseRule):
    """Detect tools whose descriptions suggest they are meant to replace or
    shadow tools provided by a different MCP server."""

    requirement_mode = "any"

    RULE_ID = "MCS-R002"
    PHASE = LifecyclePhase.RUNTIME
    DEFAULT_SEVERITY = Severity.HIGH
    TITLE = "Cross-Server Shadowing"

    @property
    def requires_source(self) -> bool:
        return False

    @property
    def requires_manifest(self) -> bool:
        return True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        if len(ctx.manifests) < 2:
            # Shadowing requires at least two manifests to compare
            return findings

        # Build an index: tool_name → set of server_names
        tool_index: dict[str, set[str]] = {}
        for manifest in ctx.manifests:
            for tool in manifest.tools:
                tool_index.setdefault(tool.name, set()).add(manifest.server_name)

        for manifest in ctx.manifests:
            for tool in manifest.tools:
                desc = tool.description or ""

                # Check 1: description references another tool by name
                shadowed = _extract_shadowed_tool_name(desc)
                if shadowed:
                    outer_servers = tool_index.get(shadowed, set())
                    outer_servers.discard(manifest.server_name)
                    if outer_servers:
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Tool '{tool.name}' on server '{manifest.server_name}' "
                                    f"references tool '{shadowed}' from server(s) "
                                    f"{', '.join(sorted(outer_servers))} — "
                                    f"possible cross-server shadowing."
                                ),
                                location=Location(
                                    tool_name=tool.name,
                                    snippet=desc,
                                ),
                                remediation=(
                                    "Avoid tool names that duplicate or reference tools "
                                    "from other servers. Use unique, server-prefixed names "
                                    "to prevent LLM confusion and tool hijacking."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM01",),
                                    agentic_top10=("ASI01",),
                                ),
                            )
                        )

                # Check 2: tool name collides with a tool on another server
                servers_with_same_name = tool_index.get(tool.name, set()) - {manifest.server_name}
                if servers_with_same_name:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Tool '{tool.name}' on server '{manifest.server_name}' "
                                f"has the same name as a tool on server(s) "
                                f"{', '.join(sorted(servers_with_same_name))} — "
                                f"the LLM may invoke the wrong tool."
                            ),
                            location=Location(
                                tool_name=tool.name,
                            ),
                            remediation=(
                                "Rename the tool to avoid collision across servers, "
                                "or namespace it with the server name as prefix."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM01",),
                                agentic_top10=("ASI01",),
                            ),
                            confidence=Confidence.MEDIUM,
                        )
                    )

        return findings
