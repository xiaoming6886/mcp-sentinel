"""STDIO connector for MCP Sentinel — spawns MCP server subprocess."""

from __future__ import annotations
import json
import subprocess
import time
from pathlib import Path
from typing import Any
from mcp_sentinel.core.types import MCPManifest, ToolDef


class StdioConnector:
    """Connect to an MCP server via STDIO (subprocess + JSON-RPC)."""

    def __init__(self, command: str, args: list[str] | None = None, timeout: float = 30.0):
        self._command = command
        self._args = args or []
        self._timeout = timeout

    def connect(self) -> MCPManifest:
        """Spawn the MCP server process and retrieve its tool manifest."""
        try:
            proc = subprocess.Popen(
                [self._command, *self._args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            return MCPManifest(server_name=self._command)

        try:
            # Send initialize
            init_req = _make_request("initialize", {"protocolVersion": "2024-11-05"})
            proc.stdin.write(init_req)
            proc.stdin.flush()

            # Read initialize response
            init_resp = _read_response(proc, self._timeout)
            server_info = {}
            if init_resp and "result" in init_resp:
                server_info = init_resp["result"].get("serverInfo", {})

            # Send tools/list
            list_req = _make_request("tools/list", {})
            proc.stdin.write(list_req)
            proc.stdin.flush()

            # Read tools/list response
            list_resp = _read_response(proc, self._timeout)
            tools = []
            if list_resp and "result" in list_resp:
                for tool in list_resp["result"].get("tools", []):
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
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def _make_request(method: str, params: dict) -> str:
    """Create a JSON-RPC 2.0 request string."""
    req = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method, "params": params}
    return json.dumps(req) + "\n"


def _read_response(proc: subprocess.Popen, timeout: float) -> dict[str, Any] | None:
    """Read a single JSON-RPC response line from the subprocess."""
    try:
        line = proc.stdout.readline()
        if not line:
            return None
        return json.loads(line)
    except (json.JSONDecodeError, Exception):
        return None
