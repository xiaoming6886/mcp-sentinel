"""MCS-D003: Source Trust — verify that MCP server packages come from trusted
registries and local paths are not in suspicious locations."""

from __future__ import annotations

import re
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Suspicious local path patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"(?:^|/)tmp/", "temporary directory (/tmp)"),
    (r"(?:^|/)Temp/", "temporary directory (Windows Temp)"),
    (r"\\Temp\\", "temporary directory (Windows Temp)"),
    (r"(?:^|/)Downloads/", "downloads directory"),
    (r"\\Downloads\\", "downloads directory (Windows)"),
    (r"(?:^|/)Desktop/", "desktop directory"),
    (r"\\Desktop\\", "desktop directory (Windows)"),
    (r"(?:^|/)\.\./", "parent directory traversal (../)"),
    (r"\.\.\\", "parent directory traversal (..\\)"),
]

# Known legitimate package registries
_KNOWN_REGISTRIES = {
    "npm": {"registry.npmjs.org", "npm.pkg.github.com"},
    "pypi": {"pypi.org", "test.pypi.org", "download.pytorch.org"},
    "docker": {"docker.io", "ghcr.io", "quay.io", "gcr.io", "mcr.microsoft.com"},
}

# Trusted local path prefixes (whitelist)
_TRUSTED_PATH_PREFIXES = {
    "/usr/local/", "/opt/", "/app/", "/home/",
    "C:\\Program Files\\",
    "${HOME}", "$HOME", "%USERPROFILE%",
}


@register_rule("MCS-D003", LifecyclePhase.DEPLOYMENT, Severity.MEDIUM, "Source Trust")
class SourceTrustRule(BaseRule):
    """Verify MCP server package sources are trusted and not from suspicious locations."""

    requires_config = True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        config = ctx.config or {}
        servers = config.get("mcpServers", {})

        if not isinstance(servers, dict) or not servers:
            return findings

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue

            command = server_cfg.get("command", "")
            args = server_cfg.get("args", [])

            if not command:
                continue

            # Determine transport type from command
            transport = self._classify_transport(command)

            if transport == "npx":
                findings.extend(
                    self._check_npx_source(server_name, command, args)
                )
            elif transport == "uvx":
                findings.extend(
                    self._check_uvx_source(server_name, command, args)
                )
            elif transport == "pip":
                findings.extend(
                    self._check_pip_source(server_name, command, args)
                )
            elif transport == "docker":
                findings.extend(
                    self._check_docker_source(server_name, command, args)
                )
            elif transport == "local":
                findings.extend(
                    self._check_local_source(server_name, command, args)
                )

        return findings

    # ------------------------------------------------------------------
    # Transport classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_transport(command: str) -> str:
        """Classify the MCP transport mechanism from the command string."""
        cmd_lower = command.lower().strip()

        # Handle full paths: /usr/bin/npx → npx
        if cmd_lower.endswith("npx") or cmd_lower.endswith("npx.exe"):
            return "npx"
        if cmd_lower.endswith("uvx") or cmd_lower.endswith("uvx.exe"):
            return "uvx"
        if cmd_lower.endswith("pip") or cmd_lower.endswith("pip.exe") or cmd_lower.endswith("pip3"):
            return "pip"
        if cmd_lower.endswith("docker") or cmd_lower.endswith("docker.exe"):
            return "docker"

        if cmd_lower in ("npx", "uvx", "pip", "pip3", "docker", "node"):
            return cmd_lower if cmd_lower != "node" else "npx"
        if cmd_lower == "python" or cmd_lower == "python3":
            return "local"

        # Heuristic: check for known tool prefixes
        if "/npx" in cmd_lower or "\\npx" in cmd_lower:
            return "npx"
        if "/uvx" in cmd_lower or "\\uvx" in cmd_lower:
            return "uvx"
        if "/docker" in cmd_lower or "\\docker" in cmd_lower:
            return "docker"

        # Default: treat as local path
        return "local"

    # ------------------------------------------------------------------
    # NPX source checks
    # ------------------------------------------------------------------

    def _check_npx_source(
        self, server_name: str, command: str, args: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # npx typically takes: npx [options] <package> [args...]
        # Look for -y / --yes followed by package name, or first positional
        pkg_name = None
        for i, arg in enumerate(args):
            if arg in ("-y", "--yes"):
                if i + 1 < len(args):
                    pkg_name = args[i + 1]
                    break
            elif not arg.startswith("-"):
                pkg_name = arg
                break

        if pkg_name and "/" not in pkg_name:
            # Scoped package check: @scope/package
            findings.append(
                self._make_finding(
                    description=(
                        f"Server '{server_name}' uses npx package '{pkg_name}' — "
                        f"verify this package is from the public npm registry"
                    ),
                    location=Location(
                        tool_name=server_name,
                        snippet=f"npx -y {pkg_name}",
                    ),
                    remediation=(
                        f"Ensure '{pkg_name}' is published on npmjs.com by a trusted "
                        f"maintainer. Consider pinning to a specific version "
                        f"(e.g., '{pkg_name}@1.2.3') and verifying its integrity hash."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM03",),
                        agentic_top10=("ASI04",),
                    ),
                    confidence=Confidence.LOW,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # UVX / pip source checks
    # ------------------------------------------------------------------

    def _check_uvx_source(
        self, server_name: str, command: str, args: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # uvx runs: uvx [options] <package> [args...]
        pkg_name = None
        for i, arg in enumerate(args):
            if arg in ("--from", "-f"):
                if i + 1 < len(args):
                    pkg_name = args[i + 1]
                    break
            elif not arg.startswith("-") and "=" not in arg:
                pkg_name = arg
                break

        if pkg_name:
            # Check if it specifies a non-PyPI index
            is_custom_index = any(
                opt in args
                for opt in ("--index-url", "--extra-index-url", "-i")
            )

            desc = (
                f"Server '{server_name}' uses uvx package '{pkg_name}'"
                + (" from a custom index" if is_custom_index else "")
                + " — verify package source trustworthiness"
            )

            findings.append(
                self._make_finding(
                    description=desc,
                    location=Location(
                        tool_name=server_name,
                        snippet=f"uvx {pkg_name}",
                    ),
                    remediation=(
                        f"Verify '{pkg_name}' is a legitimate PyPI package. "
                        f"Consider pinning to a specific version and auditing "
                        f"its source repository."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM03",),
                        agentic_top10=("ASI04",),
                    ),
                    confidence=Confidence.LOW,
                )
            )

        return findings

    def _check_pip_source(
        self, server_name: str, command: str, args: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # pip install <package>
        for i, arg in enumerate(args):
            if arg == "install" and i + 1 < len(args):
                pkg_name = args[i + 1]
                is_custom_index = "--index-url" in args or "-i" in args

                desc = (
                    f"Server '{server_name}' pip-installs '{pkg_name}'"
                    + (" from a custom index" if is_custom_index else "")
                    + " — verify package source"
                )

                findings.append(
                    self._make_finding(
                        description=desc,
                        location=Location(
                            tool_name=server_name,
                            snippet=f"pip install {pkg_name}",
                        ),
                        remediation=(
                            f"Verify '{pkg_name}' is a trusted PyPI package. "
                            f"Pin versions and use hash-checking mode "
                            f"(--require-hashes) for reproducibility."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM03",),
                            agentic_top10=("ASI04",),
                        ),
                        confidence=Confidence.LOW,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Docker source checks
    # ------------------------------------------------------------------

    def _check_docker_source(
        self, server_name: str, command: str, args: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # docker run <image>
        for i, arg in enumerate(args):
            if arg == "run" and i + 1 < len(args):
                image = args[i + 1]

                # Check if image is from a known registry
                image_parts = image.split("/")
                if len(image_parts) >= 2 and "." in image_parts[0]:
                    registry = image_parts[0]
                    known = any(
                        registry == known_reg or registry.endswith("." + known_reg)
                        for known_set in _KNOWN_REGISTRIES["docker"]
                        for known_reg in known_set
                    )
                    if not known:
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Server '{server_name}' uses Docker image '{image}' "
                                    f"from unknown registry '{registry}'"
                                ),
                                location=Location(
                                    tool_name=server_name,
                                    snippet=f"docker run {image}",
                                ),
                                remediation=(
                                    f"Verify the Docker image '{image}' is from a trusted "
                                    f"registry (Docker Hub, GHCR, etc.). Prefer official "
                                    f"or verified publisher images."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM03",),
                                    agentic_top10=("ASI04",),
                                ),
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings

    # ------------------------------------------------------------------
    # Local path checks
    # ------------------------------------------------------------------

    def _check_local_source(
        self, server_name: str, command: str, args: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check command path itself
        findings.extend(self._check_single_path(server_name, command))

        # Check args for local paths (scripts, entry points)
        for arg in args:
            if not arg.startswith("-"):
                findings.extend(self._check_single_path(server_name, arg))

        return findings

    def _check_single_path(
        self, server_name: str, path_str: str
    ) -> list[Finding]:
        """Check a single path string for trust issues."""
        findings: list[Finding] = []

        # Normalize for comparison
        normalized = path_str.replace("\\", "/")

        # Skip non-path strings (URLs, package names without slashes)
        if "/" not in normalized and "\\" not in path_str:
            return findings

        # Check trusted prefixes first
        is_trusted = any(
            normalized.startswith(prefix.replace("\\", "/"))
            for prefix in _TRUSTED_PATH_PREFIXES
        )

        # Check for variable expansion — typically OK
        if re.search(r"\$\{?\w+\}?", normalized) or re.search(r"%\w+%", path_str):
            return findings

        # Check suspicious paths
        for pattern, label in _SUSPICIOUS_PATH_PATTERNS:
            if re.search(pattern, normalized):
                findings.append(
                    self._make_finding(
                        description=(
                            f"Server '{server_name}' references a local path in "
                            f"{label}: '{path_str[:120]}'"
                        ),
                        location=Location(
                            tool_name=server_name,
                            snippet=path_str[:200],
                        ),
                        remediation=(
                            f"Move the MCP server files from {label} to a "
                            f"trusted, persistent location (e.g., /opt/mcp-servers/ "
                            f"or a project-specific directory)."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM03",),
                            agentic_top10=("ASI04",),
                        ),
                        confidence=Confidence.HIGH,
                    )
                )

        return findings
