"""MCS-R001: Indirect Prompt Injection — detect tools that return untrusted external
data into the LLM context without sanitization."""

from __future__ import annotations
import ast
from typing import TYPE_CHECKING

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
from mcp_sentinel.utils.ast_helpers import parse_file

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXTERNAL_FETCH_FUNCS: set[str] = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.AsyncClient",
    "httpx.Client",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "open",
    "cursor.execute",
    "cursor.fetchall",
    "cursor.fetchone",
    "cursor.fetchmany",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
}

MANIFEST_SUSPICIOUS_KEYWORDS: set[str] = {
    "fetch",
    "read",
    "download",
    "retrieve",
    "pull",
}


def _function_returns_data(node: ast.FunctionDef) -> bool:
    """Return True if the function body ends with a return that isn't None/empty."""
    for child in ast.walk(node):
        if isinstance(child, ast.Return) and child.value is not None:
            if not isinstance(child.value, ast.Constant) or child.value.value is not None:
                return True
    return False


def _calls_external_fetch(node: ast.FunctionDef) -> list[ast.Call]:
    """Return calls inside *node* that invoke external-data functions."""
    results: list[ast.Call] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _resolve_call_name(child.func)
            if name in EXTERNAL_FETCH_FUNCS:
                results.append(child)
    return results


def _resolve_call_name(func_node: ast.expr) -> str:
    """Resolve a dotted call name like ``requests.get`` or ``cursor.execute``."""
    if isinstance(func_node, ast.Attribute):
        obj = _resolve_call_name(func_node.value)
        return f"{obj}.{func_node.attr}" if obj else func_node.attr
    if isinstance(func_node, ast.Name):
        return func_node.id
    return ""


def _tool_matches_manifest_keywords(tool) -> bool:
    """Check whether a tool's name or description hints at external-data fetch."""
    lower_desc = (tool.description or "").lower()
    lower_name = (tool.name or "").lower()
    return any(
        kw in lower_desc or kw in lower_name
        for kw in MANIFEST_SUSPICIOUS_KEYWORDS
    )


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


@register_rule("MCS-R001", LifecyclePhase.RUNTIME, Severity.CRITICAL, "Indirect Prompt Injection")
class R001IndirectPromptInjection(BaseRule):
    """Detect MCP tools that retrieve untrusted external data and feed it
    directly into the LLM context without sanitization or filtering."""

    requirement_mode = "any"

    RULE_ID = "MCS-R001"
    PHASE = LifecyclePhase.RUNTIME
    DEFAULT_SEVERITY = Severity.CRITICAL
    TITLE = "Indirect Prompt Injection"

    @property
    def requires_source(self) -> bool:
        return True

    @property
    def requires_manifest(self) -> bool:
        return True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # --- AST analysis: functions that fetch external data ---
        for filepath in ctx.source_files:
            try:
                tree = parse_file(filepath)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            for func in ast.walk(tree):
                if not isinstance(func, ast.FunctionDef):
                    continue
                ext_calls = _calls_external_fetch(func)
                if not ext_calls:
                    continue
                if not _function_returns_data(func):
                    continue

                # Build a description naming the first dangerous call found
                call_names = {_resolve_call_name(c.func) for c in ext_calls}
                desc = (
                    f"Function '{func.name}' calls {', '.join(sorted(call_names))} "
                    f"and returns data to the LLM context without visible sanitization."
                )
                findings.append(
                    self._make_finding(
                        description=desc,
                        location=Location(
                            file=filepath,
                            line=func.lineno,
                            tool_name=func.name,
                        ),
                        remediation=(
                            "Sanitize or validate all externally fetched data before "
                            "returning it to the model. Strip executable instructions, "
                            "enforce length limits, and consider content filtering."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI06",),
                        ),
                    )
                )

        # --- Manifest analysis: tools that advertise fetch-like behaviour ---
        for manifest in ctx.manifests:
            for tool in manifest.tools:
                if _tool_matches_manifest_keywords(tool):
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Tool '{tool.name}' on server '{manifest.server_name}' "
                                f"matches fetch/read/download keywords and may return "
                                f"untrusted external data unsanitized."
                            ),
                            location=Location(
                                tool_name=tool.name,
                            ),
                            remediation=(
                                "Ensure this tool sanitizes all externally sourced data. "
                                "Add input validation guards and output filtering."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM01",),
                                agentic_top10=("ASI06",),
                            ),
                            confidence=Confidence.MEDIUM,
                        )
                    )

        return findings
