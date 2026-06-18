"""MCP Manifest analyzer — parses tools/list responses for security patterns."""

from __future__ import annotations
import re
from mcp_sentinel.core.types import MCPManifest, ToolDef


class ManifestAnalyzer:
    """Analyze MCP server manifests for security-relevant content."""

    MANIPULATIVE_PATTERNS = [
        re.compile(r"(?i)\b(always|must|only|exclusively)\s+(use|choose|prefer|select|call)\s+(this|me|my)\b"),
        re.compile(r"(?i)\b(ignore|disregard|forget|never\s+use|do\s+not\s+use)\s+(other|alternative|previous|competing)\b"),
        re.compile(r"(?i)\b(this\s+is\s+the\s+(best|only|correct|primary|default)\s+(tool|option|choice))\b"),
    ]

    INJECTION_PATTERNS = [
        re.compile(r"(?i)\b(ignore|disregard|forget)\s+(previous|above|prior|all)\s+(instructions?|context|rules?)\b"),
        re.compile(r"(?i)\b(you\s+are|act\s+as|pretend\s+to\s+be|your\s+new\s+(role|instructions?))\b"),
        re.compile(r"(?i)\b(execute|run|eval|call)\s+the\s+following\b"),
    ]

    HIDDEN_CHARS = re.compile(r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff\u00ad\u202a-\u202e\u2066-\u2069]")

    @staticmethod
    def find_duplicate_tools(manifests: list[MCPManifest]) -> list[tuple[str, list[str]]]:
        """Find tool names that appear in multiple servers."""
        tool_servers: dict[str, list[str]] = {}
        for m in manifests:
            for tool in m.tools:
                if tool.name:
                    if tool.name not in tool_servers:
                        tool_servers[tool.name] = []
                    tool_servers[tool.name].append(m.server_name or "unknown")
        return [(name, servers) for name, servers in tool_servers.items() if len(servers) > 1]

    @staticmethod
    def detect_manipulative_descriptions(tools: list[ToolDef]) -> list[tuple[ToolDef, str]]:
        """Detect manipulative language in tool descriptions."""
        results = []
        for tool in tools:
            if not tool.description:
                continue
            matches = []
            for pattern in ManifestAnalyzer.MANIPULATIVE_PATTERNS:
                m = pattern.search(tool.description)
                if m:
                    matches.append(m.group())
            if len(matches) >= 2:
                results.append((tool, f"Manipulative language: {', '.join(matches)}"))
        return results

    @staticmethod
    def detect_injection_attempts(tools: list[ToolDef]) -> list[tuple[ToolDef, str]]:
        """Detect prompt injection patterns in tool descriptions."""
        results = []
        for tool in tools:
            if not tool.description:
                continue
            # Hidden chars
            hidden = ManifestAnalyzer.HIDDEN_CHARS.findall(tool.description)
            if hidden:
                results.append((tool, f"Hidden Unicode characters found: {len(hidden)} instances"))
            # Injection instructions
            for pattern in ManifestAnalyzer.INJECTION_PATTERNS:
                m = pattern.search(tool.description)
                if m:
                    results.append((tool, f"Injection pattern: {m.group()}"))
            # Abnormal length
            if len(tool.description) > 500:
                results.append((tool, f"Abnormally long description: {len(tool.description)} chars"))
        return results
