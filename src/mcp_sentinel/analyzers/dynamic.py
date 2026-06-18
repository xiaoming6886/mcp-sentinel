"""Dynamic analyzer for live MCP server probing."""

from __future__ import annotations
from mcp_sentinel.core.types import MCPManifest, ToolDef


class DynamicAnalyzer:
    """Probe a live MCP server via JSON-RPC for runtime security analysis."""

    @staticmethod
    def analyze_manifest(manifest: MCPManifest) -> list[dict]:
        """Analyze a live MCP server manifest for runtime security concerns."""
        results = []
        tool_names = {t.name for t in manifest.tools if t.name}
        descriptions = [t.description for t in manifest.tools if t.description]

        # Check for shadowing: tools with descriptions that reference other tools
        for tool in manifest.tools:
            if not tool.description:
                continue
            for other_name in tool_names:
                if other_name != tool.name and other_name in tool.description:
                    results.append({
                        "type": "shadowing_reference",
                        "tool": tool.name,
                        "references": other_name,
                    })

        # Check for capability enumeration: tools that can read/write/execute
        capabilities = {
            "read": {"read", "fetch", "get", "list", "search", "query", "view", "open"},
            "write": {"write", "save", "create", "update", "delete", "remove", "modify", "set"},
            "execute": {"exec", "run", "execute", "call", "invoke", "spawn", "launch"},
            "network": {"http", "api", "url", "download", "upload", "send", "connect"},
        }
        for tool in manifest.tools:
            tool_caps = set()
            desc_lower = (tool.name + " " + tool.description).lower()
            for cap, keywords in capabilities.items():
                if any(kw in desc_lower for kw in keywords):
                    tool_caps.add(cap)
            if len(tool_caps) >= 2:
                results.append({
                    "type": "multi_capability",
                    "tool": tool.name,
                    "capabilities": list(tool_caps),
                })

        return results
