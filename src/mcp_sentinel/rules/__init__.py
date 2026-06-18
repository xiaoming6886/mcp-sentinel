"""MCP Sentinel detection rules.

Importing this package registers all rules via @register_rule decorators.
"""
from mcp_sentinel.rules import creation  # noqa: F401
from mcp_sentinel.rules import deployment  # noqa: F401
from mcp_sentinel.rules import runtime  # noqa: F401
from mcp_sentinel.rules import maintenance  # noqa: F401
