"""Creation-phase detection rules — MCS Sentinel.

Imports trigger @register_rule decorators to self-register
each rule with the global RuleRegistry.
"""

from mcp_sentinel.rules.creation.c001_namespace_typosquatting import NamespaceTyposquattingRule  # noqa: F401
from mcp_sentinel.rules.creation.c002_tool_name_conflict import ToolNameConflictRule  # noqa: F401
from mcp_sentinel.rules.creation.c003_preference_manipulation import PreferenceManipulationRule  # noqa: F401
from mcp_sentinel.rules.creation.c004_tool_poisoning import ToolPoisoningRule  # noqa: F401
from mcp_sentinel.rules.creation.c005_command_injection import CommandInjectionRule  # noqa: F401
from mcp_sentinel.rules.creation.c006_installer_integrity import InstallerIntegrityRule  # noqa: F401

__all__ = [
    "NamespaceTyposquattingRule",
    "ToolNameConflictRule",
    "PreferenceManipulationRule",
    "ToolPoisoningRule",
    "CommandInjectionRule",
    "InstallerIntegrityRule",
]
