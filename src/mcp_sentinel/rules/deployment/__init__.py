"""Deployment-phase detection rules — MCS Sentinel.

Imports trigger @register_rule decorators to self-register
each rule with the global RuleRegistry.
"""

from mcp_sentinel.rules.deployment.d001_credential_exposure import CredentialExposureRule  # noqa: F401
from mcp_sentinel.rules.deployment.d002_sandbox_config import SandboxConfigRule  # noqa: F401
from mcp_sentinel.rules.deployment.d003_source_trust import SourceTrustRule  # noqa: F401

__all__ = [
    "CredentialExposureRule",
    "SandboxConfigRule",
    "SourceTrustRule",
]
