"""MCP Sentinel — Runtime-phase detection rules.

Importing this package triggers @register_rule for all runtime rules,
which adds them to the global rule registry.
"""

from mcp_sentinel.rules.runtime.r001_indirect_prompt_injection import R001IndirectPromptInjection  # noqa: F401
from mcp_sentinel.rules.runtime.r002_cross_server_shadowing import R002CrossServerShadowing  # noqa: F401
from mcp_sentinel.rules.runtime.r003_tool_chain_abuse import R003ToolChainAbuse  # noqa: F401
from mcp_sentinel.rules.runtime.r004_unauthorized_access import R004UnauthorizedAccess  # noqa: F401
from mcp_sentinel.rules.runtime.r005_sandbox_escape import R005SandboxEscape  # noqa: F401

__all__ = [
    "R001IndirectPromptInjection",
    "R002CrossServerShadowing",
    "R003ToolChainAbuse",
    "R004UnauthorizedAccess",
    "R005SandboxEscape",
]
