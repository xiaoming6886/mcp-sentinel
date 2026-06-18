"""MCS-M003: Configuration Drift — compare current MCP configuration against
a baseline snapshot to detect unexpected changes."""

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


def _hash_dict(d: dict) -> str:
    """Simple deterministic string representation for comparison."""
    import json

    return json.dumps(d, sort_keys=True, default=str)


@register_rule("MCS-M003", LifecyclePhase.MAINTENANCE, Severity.LOW, "Configuration Drift")
class ConfigDriftRule(BaseRule):
    """Detect configuration drift by comparing current scan context against
    a baseline snapshot from a prior scan."""

    requires_config = True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        baseline = ctx.baseline
        if not baseline or not isinstance(baseline, dict):
            return findings

        config = ctx.config or {}
        servers = config.get("mcpServers", {})

        if not isinstance(servers, dict):
            return findings

        baseline_servers = baseline.get("mcpServers", {})
        if not isinstance(baseline_servers, dict):
            return findings

        current_names = set(servers)
        baseline_names = set(baseline_servers)

        # --- Drift 1: New servers added ---
        new_servers = current_names - baseline_names
        for name in sorted(new_servers):
            num_tools = self._count_tools(servers.get(name, {}))
            findings.append(
                self._make_finding(
                    description=(
                        f"New MCP server '{name}' added since baseline"
                        + (f" (declares {num_tools} tools)" if num_tools else "")
                    ),
                    location=Location(
                        tool_name=name,
                        snippet=f"New server: {name}",
                    ),
                    remediation=(
                        f"Review the new server '{name}' for trustworthiness. "
                        f"Verify its package source and audit its declared tools "
                        f"before allowing access to sensitive data."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM03",),
                        agentic_top10=("ASI04",),
                    ),
                    metadata={
                        "drift_type": "server_added",
                        "server": name,
                        "tool_count": num_tools,
                    },
                )
            )

        # --- Drift 2: Servers removed ---
        removed_servers = baseline_names - current_names
        for name in sorted(removed_servers):
            num_tools = self._count_tools(baseline_servers.get(name, {}))
            findings.append(
                self._make_finding(
                    description=(
                        f"MCP server '{name}' removed since baseline"
                        + (f" (previously had {num_tools} tools)" if num_tools else "")
                    ),
                    location=Location(
                        tool_name=name,
                        snippet=f"Removed server: {name}",
                    ),
                    remediation=(
                        f"Verify that removal of server '{name}' was intentional. "
                        f"Check that no dependent workflows still reference its tools."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM03",),
                        agentic_top10=("ASI04",),
                    ),
                    metadata={
                        "drift_type": "server_removed",
                        "server": name,
                    },
                )
            )

        # --- Drift 3: Server config changed (same name, different settings) ---
        for name in sorted(current_names & baseline_names):
            current_entry = servers[name]
            baseline_entry = baseline_servers[name]

            if not isinstance(current_entry, dict) or not isinstance(baseline_entry, dict):
                continue

            changes = self._diff_server_config(name, current_entry, baseline_entry)
            findings.extend(changes)

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_tools(server_cfg: dict) -> int:
        """Count declared tools in a server config entry."""
        if not isinstance(server_cfg, dict):
            return 0
        tools = server_cfg.get("tools", [])
        return len(tools) if isinstance(tools, list) else 0

    def _diff_server_config(
        self,
        server_name: str,
        current: dict,
        baseline: dict,
    ) -> list[Finding]:
        """Compare current and baseline server configs and flag meaningful changes."""
        findings: list[Finding] = []

        # --- Check command ---
        current_cmd = current.get("command", "")
        baseline_cmd = baseline.get("command", "")
        if current_cmd != baseline_cmd and current_cmd and baseline_cmd:
            findings.append(
                self._make_finding(
                    description=(
                        f"Server '{server_name}' command changed: "
                        f"'{baseline_cmd}' → '{current_cmd}'"
                    ),
                    location=Location(
                        tool_name=server_name,
                        snippet=f"command: {current_cmd}",
                    ),
                    remediation=(
                        f"Verify the command change for server '{server_name}' is "
                        f"authorized. Unauthorized command changes could indicate "
                        f"a supply-chain attack."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM03",),
                        agentic_top10=("ASI04",),
                    ),
                    confidence=Confidence.MEDIUM,
                    metadata={
                        "drift_type": "command_changed",
                        "server": server_name,
                        "old_command": baseline_cmd,
                        "new_command": current_cmd,
                    },
                )
            )

        # --- Check args ---
        current_args = current.get("args", [])
        baseline_args = baseline.get("args", [])
        if (
            isinstance(current_args, list)
            and isinstance(baseline_args, list)
            and current_args != baseline_args
        ):
            # Only flag if args actually differ (not just reordered)
            added = set(current_args) - set(baseline_args)
            removed = set(baseline_args) - set(current_args)
            if added or removed:
                details = []
                if added:
                    details.append(f"added: {', '.join(sorted(added))}")
                if removed:
                    details.append(f"removed: {', '.join(sorted(removed))}")
                findings.append(
                    self._make_finding(
                        description=(
                            f"Server '{server_name}' args changed — "
                            f"{'; '.join(details)}"
                        ),
                        location=Location(
                            tool_name=server_name,
                            snippet=f"args: {current_args}",
                        ),
                        remediation=(
                            f"Review argument changes for server '{server_name}'. "
                            f"Ensure new arguments don't introduce additional "
                            f"privileges or change execution context."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM03",),
                            agentic_top10=("ASI04",),
                        ),
                        confidence=Confidence.LOW,
                        metadata={
                            "drift_type": "args_changed",
                            "server": server_name,
                            "added_args": sorted(added),
                            "removed_args": sorted(removed),
                        },
                    )
                )

        # --- Check env vars ---
        current_env = current.get("env", {})
        baseline_env = baseline.get("env", {})

        if isinstance(current_env, dict) and isinstance(baseline_env, dict):
            env_added = set(current_env) - set(baseline_env)
            env_removed = set(baseline_env) - set(current_env)

            if env_added:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Server '{server_name}' has new env vars: "
                            f"{', '.join(sorted(env_added))}"
                        ),
                        location=Location(
                            tool_name=server_name,
                            snippet=f"New env vars: {', '.join(sorted(env_added))}",
                        ),
                        remediation=(
                            f"Review new environment variables for server "
                            f"'{server_name}'. Ensure they don't introduce "
                            f"unnecessary privileges or secrets exposure."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM03",),
                            agentic_top10=("ASI04",),
                        ),
                        metadata={
                            "drift_type": "env_added",
                            "server": server_name,
                            "added_env": sorted(env_added),
                        },
                    )
                )

            if env_removed:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Server '{server_name}' env vars removed: "
                            f"{', '.join(sorted(env_removed))}"
                        ),
                        location=Location(
                            tool_name=server_name,
                            snippet=f"Removed env vars: {', '.join(sorted(env_removed))}",
                        ),
                        remediation=(
                            f"Verify that removal of env vars "
                            f"{', '.join(sorted(env_removed))} was intentional "
                            f"and doesn't break server '{server_name}'."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM03",),
                            agentic_top10=("ASI04",),
                        ),
                        metadata={
                            "drift_type": "env_removed",
                            "server": server_name,
                            "removed_env": sorted(env_removed),
                        },
                    )
                )

        return findings
