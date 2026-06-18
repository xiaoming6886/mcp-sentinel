"""MCP client config analyzer for MCP Sentinel."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any


class ConfigAnalyzer:
    """Parse MCP client configuration files for security analysis."""

    @staticmethod
    def parse(path: Path) -> dict[str, Any]:
        """Parse an MCP client config file (JSON/JSONC)."""
        try:
            text = path.read_text(encoding="utf-8")
            # Strip JSONC comments
            text = ConfigAnalyzer._strip_comments(text)
            return json.loads(text)
        except Exception:
            return {}

    @staticmethod
    def _strip_comments(text: str) -> str:
        """Remove // and /* */ comments from JSONC."""
        lines = []
        in_block = False
        for line in text.split("\n"):
            if in_block:
                idx = line.find("*/")
                if idx >= 0:
                    line = line[idx + 2 :]
                    in_block = False
                else:
                    continue
            # Remove // comments
            idx = line.find("//")
            if idx >= 0:
                # Check it's not inside a string
                before = line[:idx]
                if before.count('"') % 2 == 0:
                    line = before
            # Check for /* */ block comments
            idx = line.find("/*")
            if idx >= 0:
                before = line[:idx]
                after = line[idx + 2 :]
                end_idx = after.find("*/")
                if end_idx >= 0:
                    line = before + after[end_idx + 2 :]
                else:
                    line = before
                    in_block = True
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def extract_servers(config: dict) -> list[dict]:
        """Extract MCP server configurations from client config."""
        servers = []
        mcp_servers = config.get("mcpServers", {})
        for name, server in mcp_servers.items():
            servers.append({
                "name": name,
                "command": server.get("command", ""),
                "args": server.get("args", []),
                "env": server.get("env", {}),
                "url": server.get("url", ""),
                "disabled": server.get("disabled", False),
            })
        return servers

    @staticmethod
    def find_plaintext_secrets(config: dict) -> list[tuple[str, str]]:
        """Find plaintext secrets in MCP client config env blocks."""
        findings = []
        sensitive_keys = {"API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH"}
        servers = ConfigAnalyzer.extract_servers(config)
        for server in servers:
            for key, value in server.get("env", {}).items():
                if isinstance(value, str) and len(value) > 8 and not value.startswith("$"):
                    for sk in sensitive_keys:
                        if sk.lower() in key.lower():
                            findings.append((server["name"], f"{key}={value[:8]}..."))
                            break
        return findings
