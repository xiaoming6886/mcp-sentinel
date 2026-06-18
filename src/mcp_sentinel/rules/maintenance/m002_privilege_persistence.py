"""MCS-M002: Privilege Persistence — detect credential-bearing environment
variables that remain in MCP config after the tools that used them were removed."""

from __future__ import annotations

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    Finding,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule

# Environment variable names that suggest credentials
_CREDENTIAL_KEY_PATTERNS: list[str] = [
    "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSPHRASE",
    "CREDENTIAL", "AUTH", "CERT",
]


def _is_credential_env_key(env_key: str) -> bool:
    """Check if an environment variable name suggests it holds a credential."""
    upper = env_key.upper().replace("_", "")
    return any(pattern in upper for pattern in _CREDENTIAL_KEY_PATTERNS)


@register_rule("MCS-M002", LifecyclePhase.MAINTENANCE, Severity.MEDIUM, "Privilege Persistence")
class PrivilegePersistenceRule(BaseRule):
    """Detect orphaned credential env vars that persist after tool removal."""

    requires_config = True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        baseline = ctx.baseline
        if not baseline or not isinstance(baseline, dict):
            # Without a baseline we cannot detect removal
            return findings

        config = ctx.config or {}
        servers = config.get("mcpServers", {})

        if not isinstance(servers, dict):
            return findings

        baseline_servers = baseline.get("mcpServers", {})
        if not isinstance(baseline_servers, dict):
            return findings

        # Collect current credential env vars per server
        current_creds: dict[str, set[str]] = {}
        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            env = server_cfg.get("env", {})
            if isinstance(env, dict):
                cred_keys = {
                    k for k in env if _is_credential_env_key(k)
                }
                if cred_keys:
                    current_creds[server_name] = cred_keys

        # Collect baseline credential env vars per server
        baseline_creds: dict[str, set[str]] = {}
        for server_name, server_cfg in baseline_servers.items():
            if not isinstance(server_cfg, dict):
                continue
            env = server_cfg.get("env", {})
            if isinstance(env, dict):
                cred_keys = {
                    k for k in env if _is_credential_env_key(k)
                }
                if cred_keys:
                    baseline_creds[server_name] = cred_keys

        # --- Detection 1: Server removed entirely but had credential env vars ---
        removed_servers = set(baseline_creds) - set(servers)
        for server_name in removed_servers:
            creds = baseline_creds[server_name]
            findings.append(
                self._make_finding(
                    description=(
                        f"Server '{server_name}' was removed but previously had "
                        f"credential env vars: {', '.join(sorted(creds))}. "
                        f"These may still be present in the environment or .env file."
                    ),
                    location=Location(
                        tool_name=server_name,
                        snippet=f"Removed server with credentials: {', '.join(sorted(creds))}",
                    ),
                    remediation=(
                        f"Verify that credential env vars {', '.join(sorted(creds))} "
                        f"for removed server '{server_name}' have been cleaned up from "
                        f"the environment, .env files, and any secrets manager. "
                        f"Rotate these credentials as a precaution."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM06",),
                        agentic_top10=("ASI03",),
                    ),
                    confidence=Confidence.MEDIUM,
                    metadata={
                        "removed_server": server_name,
                        "orphaned_creds": sorted(creds),
                    },
                )
            )

        # --- Detection 2: Server still exists but credential env vars changed ---
        for server_name in set(current_creds) & set(baseline_creds):
            removed_creds = baseline_creds[server_name] - current_creds[server_name]
            if removed_creds:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Server '{server_name}' still exists but credential env "
                            f"vars were removed: {', '.join(sorted(removed_creds))}. "
                            f"These may persist externally."
                        ),
                        location=Location(
                            tool_name=server_name,
                            snippet=f"Dropped credentials: {', '.join(sorted(removed_creds))}",
                        ),
                        remediation=(
                            f"Ensure credential env vars {', '.join(sorted(removed_creds))} "
                            f"for server '{server_name}' are revoked or removed from all "
                            f"locations (env files, CI/CD configs, secrets manager)."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI03",),
                        ),
                        confidence=Confidence.LOW,
                        metadata={
                            "server": server_name,
                            "removed_creds": sorted(removed_creds),
                        },
                    )
                )

        return findings
