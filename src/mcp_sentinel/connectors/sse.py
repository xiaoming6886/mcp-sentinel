"""SSE connector for MCP Sentinel — connects to remote MCP servers."""

from __future__ import annotations
import json
import time
from mcp_sentinel.core.types import MCPManifest, ToolDef


class SSEConnector:
    """Connect to an MCP server via SSE (Server-Sent Events over HTTP)."""

    def __init__(self, url: str, timeout: float = 30.0):
        self._url = url.rstrip("/")
        self._timeout = timeout

    def connect(self) -> MCPManifest:
        """Connect to the MCP server and retrieve its manifest."""
        import httpx

        try:
            with httpx.Client(timeout=self._timeout) as client:
                # Connect to SSE endpoint
                resp = client.get(f"{self._url}/sse", headers={"Accept": "text/event-stream"})
                if resp.status_code != 200:
                    return MCPManifest(server_name=f"SSE@{self._url}")

                # Send initialize via POST
                init_resp = client.post(
                    f"{self._url}/message",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2024-11-05"},
                    },
                )
                server_info = {}
                if init_resp.status_code == 200:
                    data = init_resp.json()
                    server_info = data.get("result", {}).get("serverInfo", {})

                # Send tools/list
                list_resp = client.post(
                    f"{self._url}/message",
                    json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                )
                tools = []
                if list_resp.status_code == 200:
                    data = list_resp.json()
                    for tool in data.get("result", {}).get("tools", []):
                        tools.append(
                            ToolDef(
                                name=tool.get("name", ""),
                                description=tool.get("description", ""),
                                server_name=server_info.get("name", ""),
                            )
                        )

                return MCPManifest(
                    server_name=server_info.get("name", ""),
                    server_version=server_info.get("version", ""),
                    tools=tools,
                )
        except Exception:
            return MCPManifest(server_name=f"SSE@{self._url}")
