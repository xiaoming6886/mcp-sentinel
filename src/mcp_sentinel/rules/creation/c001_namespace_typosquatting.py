"""MCS-C001: Namespace Typosquatting Detection.

Detects MCP servers whose names are typo-squatted versions of known legitimate servers,
using Jaro-Winkler similarity and Levenshtein distance against a curated allowlist.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule
from mcp_sentinel.utils.similarity import is_typosquat


@register_rule("MCS-C001", LifecyclePhase.CREATION, Severity.HIGH, "Namespace Typosquatting")
class NamespaceTyposquattingRule(BaseRule):
    """Flag server names that are typographical mimics of well-known MCP servers."""

    requires_manifest = True

    JW_THRESHOLD = 0.85
    LD_MAX = 2

    def _load_known_servers(self) -> list[str]:
        """Load the curated allowlist from data/known_servers.json."""
        candidates = [
            # Resolve from package root: mcp_sentinel/data/known_servers.json
            Path(__file__).resolve().parents[3] / "data" / "known_servers.json",
            # Fallback: relative to working directory
            Path("data") / "known_servers.json",
        ]
        for candidate in candidates:
            if candidate.exists():
                raw = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    return raw
        return []

    def check(self, ctx: ScanContext) -> list:
        findings: list = []

        manifest = ctx.manifest
        if manifest is None:
            return findings

        server_name = (manifest.server_name or "").strip()
        if not server_name:
            return findings

        known = self._load_known_servers()
        if not known:
            return findings

        # Reject exact matches — those are legitimate
        if server_name.lower() in {k.lower() for k in known}:
            return findings

        # Check for typosquat candidates
        hits = is_typosquat(server_name, known, threshold=self.JW_THRESHOLD)
        for known_name, jw_score, ld_distance in hits:
            if ld_distance <= self.LD_MAX:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Server name '{server_name}' is a potential typosquat of "
                            f"known server '{known_name}' "
                            f"(Jaro-Winkler={jw_score:.3f}, Levenshtein={ld_distance})"
                        ),
                        location=Location(
                            tool_name=server_name,
                            snippet=f"server_name: {server_name}",
                        ),
                        remediation=(
                            f"Verify the authenticity of '{server_name}'. "
                            f"If it is a legitimate fork or variant, add it to the known servers allowlist. "
                            f"Otherwise, replace with the canonical name '{known_name}' or remove this server."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM03",),
                            agentic_top10=("ASI04",),
                        ),
                        confidence=Confidence.HIGH,
                    )
                )

        return findings
