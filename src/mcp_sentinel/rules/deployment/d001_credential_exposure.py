"""MCS-D001: Credential Exposure — detect hardcoded API keys, tokens, and secrets
in source files and MCP client configuration."""

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
from mcp_sentinel.utils.entropy import is_high_entropy

# ---------------------------------------------------------------------------
# Known API key / token patterns (prefix-based)
# Each tuple: (pattern, label, confidence)
# ---------------------------------------------------------------------------

_API_KEY_PATTERNS: list[tuple[str, str, Confidence]] = [
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API Key", Confidence.HIGH),
    (r"sk-proj-[A-Za-z0-9_-]{20,}", "OpenAI Project Key", Confidence.HIGH),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Confidence.HIGH),
    (r"github_pat_[A-Za-z0-9_]{36,}", "GitHub Fine-grained Token", Confidence.HIGH),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Confidence.HIGH),
    (r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]+", "Slack Bot Token", Confidence.HIGH),
    (r"xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]+", "Slack User Token", Confidence.HIGH),
    (r"glpat-[A-Za-z0-9\-]{20,}", "GitLab Personal Access Token", Confidence.HIGH),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "Bearer/Base64 Token", Confidence.MEDIUM),
]

# Credential-suggesting variable names (case-insensitive substring match)
_CREDENTIAL_VAR_PATTERNS: list[str] = [
    "api_key", "apikey", "api_secret", "apisecret",
    "secret", "secret_key", "secretkey",
    "token", "auth_token", "authtoken", "access_token", "accesstoken",
    "password", "passwd", "passphrase",
    "credential", "credentials",
    "auth", "authorization", "authorisation",
    "private_key", "privatekey",
]

# Regex to capture string literal assignments: var = "value" or var = 'value'
_STRING_ASSIGN_RE = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*   # variable name
        (['\"])(?P<value>.*?)\2""",
    re.VERBOSE,
)


@register_rule("MCS-D001", LifecyclePhase.DEPLOYMENT, Severity.CRITICAL, "Credential Exposure")
class CredentialExposureRule(BaseRule):
    """Detect hardcoded API keys, tokens, and secrets in source and config."""

    requires_source = True
    requires_config = True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # --- Phase 1: scan source files for API key patterns ---
        findings.extend(self._scan_source_files(ctx))

        # --- Phase 2: scan config for plaintext secrets in env blocks ---
        findings.extend(self._scan_config_env(ctx))

        return findings

    # ------------------------------------------------------------------
    # Phase 1: source file scanning
    # ------------------------------------------------------------------

    def _scan_source_files(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for file_path in ctx.source_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError):
                continue

            lines = content.splitlines()

            # 1a – known API key prefix patterns
            for pattern, label, confidence in _API_KEY_PATTERNS:
                compiled = re.compile(pattern)
                for idx, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    # skip comments to reduce noise
                    if stripped.lstrip().startswith("#") or stripped.lstrip().startswith("//"):
                        continue
                    match = compiled.search(stripped)
                    if match:
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Hardcoded {label} found in {file_path.name}:{idx} — "
                                    f"matched prefix pattern '{match.group()[:24]}...'"
                                ),
                                location=Location(
                                    file=file_path,
                                    line=idx,
                                    snippet=stripped[:200],
                                ),
                                remediation=(
                                    f"Remove the hardcoded {label} and use environment variables "
                                    f"or a secrets manager. Rotate the exposed credential immediately."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM02",),
                                    agentic_top10=("ASI03",),
                                ),
                                confidence=confidence,
                            )
                        )

            # 1b – Shannon entropy on string literals with credential-suggesting variable names
            for match in _STRING_ASSIGN_RE.finditer(content):
                var_name = match.group(1).lower().replace("_", "")
                value = match.group("value")

                # skip empty / very short values
                if len(value) < 8:
                    continue

                # check if variable name suggests a credential
                if not any(pattern in var_name for pattern in _CREDENTIAL_VAR_PATTERNS):
                    continue

                # skip obvious non-secret placeholders
                if value in ("", "your-api-key", "YOUR_API_KEY", "changeme", "REPLACE_ME"):
                    continue

                if is_high_entropy(value, threshold=4.5):
                    # locate the line number
                    line_no = content[:match.start()].count("\n") + 1

                    findings.append(
                        self._make_finding(
                            description=(
                                f"High-entropy string assigned to credential-like variable "
                                f"'{match.group(1)}' in {file_path.name}:{line_no}"
                            ),
                            location=Location(
                                file=file_path,
                                line=line_no,
                                snippet=f"{match.group(1)} = '***'",
                            ),
                            remediation=(
                                f"Replace the hardcoded value in '{match.group(1)}' with an "
                                f"environment variable reference or secrets manager call."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM02",),
                                agentic_top10=("ASI03",),
                            ),
                            confidence=Confidence.MEDIUM,
                            metadata={"var_name": match.group(1)},
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Phase 2: config env block inspection
    # ------------------------------------------------------------------

    def _scan_config_env(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # Check top-level "env" dict
        config = ctx.config or {}

        top_env = config.get("env", {})
        if isinstance(top_env, dict):
            findings.extend(self._check_env_block(top_env, "top-level env block"))

        # Check per-server env blocks
        servers = config.get("mcpServers", {})
        if isinstance(servers, dict):
            for server_name, server_cfg in servers.items():
                if not isinstance(server_cfg, dict):
                    continue
                server_env = server_cfg.get("env", {})
                if isinstance(server_env, dict):
                    findings.extend(
                        self._check_env_block(
                            server_env,
                            f"server '{server_name}' env block",
                        )
                    )

        return findings

    def _check_env_block(
        self,
        env_dict: dict[str, str],
        source_desc: str,
    ) -> list[Finding]:
        """Check an env dict for plaintext credential values."""
        findings: list[Finding] = []

        for key, value in env_dict.items():
            if not isinstance(value, str) or not value.strip():
                continue

            key_lower = key.lower().replace("_", "")
            is_credential_key = any(
                pattern in key_lower for pattern in _CREDENTIAL_VAR_PATTERNS
            )

            # Check known API key prefixes
            for pattern, label, confidence in _API_KEY_PATTERNS:
                if re.search(pattern, value):
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Plaintext {label} found in {source_desc} "
                                f"under env key '{key}'"
                            ),
                            location=Location(
                                snippet=f"{key}=***",
                            ),
                            remediation=(
                                f"Move the {label} to a secure secrets manager. "
                                f"If it must be in env, use an external .env file "
                                f"that is excluded from version control."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM02",),
                                agentic_top10=("ASI03",),
                            ),
                            confidence=confidence,
                        )
                    )

            # High-entropy check on credential-keyed values
            if is_credential_key and is_high_entropy(value, threshold=4.0):
                findings.append(
                    self._make_finding(
                        description=(
                            f"High-entropy value in {source_desc} under "
                            f"credential-suggesting env key '{key}'"
                        ),
                        location=Location(snippet=f"{key}=***"),
                        remediation=(
                            f"Move the value of '{key}' to a secrets manager "
                            f"to avoid plaintext exposure in config."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM02",),
                            agentic_top10=("ASI03",),
                        ),
                        confidence=Confidence.MEDIUM,
                        metadata={"env_key": key},
                    )
                )

        return findings
