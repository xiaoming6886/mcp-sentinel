"""Maintenance-phase detection rules — MCS Sentinel.

Imports trigger @register_rule decorators to self-register
each rule with the global RuleRegistry.
"""

from mcp_sentinel.rules.maintenance.m001_vulnerable_version import VulnerableVersionRule  # noqa: F401
from mcp_sentinel.rules.maintenance.m002_privilege_persistence import PrivilegePersistenceRule  # noqa: F401
from mcp_sentinel.rules.maintenance.m003_config_drift import ConfigDriftRule  # noqa: F401

__all__ = [
    "VulnerableVersionRule",
    "PrivilegePersistenceRule",
    "ConfigDriftRule",
]
