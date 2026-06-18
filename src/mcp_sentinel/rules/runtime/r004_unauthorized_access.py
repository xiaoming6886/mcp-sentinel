"""MCS-R004: Unauthorized Access — detect tools that access files / paths / URLs
without proper path-traversal or input-validation guards."""

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

UNRESTRICTED_PATH_FUNCTIONS: set[str] = {
    "open",
    "Path",
    "pathlib.Path",
}

MANIFEST_UNSAFE_PARAM_KEYWORDS: set[str] = {
    "path",
    "file",
    "filename",
    "filepath",
    "url",
    "command",
    "cmd",
    "executable",
    "template",
}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _is_variable(node: ast.expr) -> str | None:
    """Return the variable name if *node* is a plain Name, else None."""
    if isinstance(node, ast.Name):
        return node.id
    return None


def _has_path_validation(func: ast.FunctionDef, var_name: str) -> bool:
    """Check whether *func* contains a Path.resolve() + is_relative_to()
    guard for *var_name* before using it in an open/Path call."""
    resolved_vars: set[str] = set()
    checked_vars: set[str] = set()

    for node in ast.walk(func):
        # Track: var = Path(var).resolve()
        if isinstance(node, ast.Assign):
            for target in node.targets if isinstance(node.targets, list) else [node.targets]:
                target_name = _is_variable(target)
                if target_name and isinstance(node.value, ast.Call):
                    call_name = _resolve_call_name(node.value.func)
                    if call_name == "Path.resolve":
                        # Check if it's Path(some_var).resolve()
                        if node.value.func.value and isinstance(node.value.func.value, ast.Call):
                            inner_call = node.value.func.value
                            if _resolve_call_name(inner_call.func) == "Path" and inner_call.args:
                                inner_var = _is_variable(inner_call.args[0])
                                if inner_var == var_name:
                                    resolved_vars.add(target_name)

        # Track: resolved_var.is_relative_to(...)
        if isinstance(node, ast.Call):
            call_name = _resolve_call_name(node.func)
            if call_name.endswith(".is_relative_to"):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in resolved_vars or node.func.value.id == var_name:
                        checked_vars.add(node.func.value.id)

    return var_name in checked_vars or bool(resolved_vars & checked_vars)


def _resolve_call_name(func_node: ast.expr) -> str:
    """Resolve a dotted call name like ``pathlib.Path`` or ``os.path.join``."""
    if isinstance(func_node, ast.Attribute):
        obj = _resolve_call_name(func_node.value)
        return f"{obj}.{func_node.attr}" if obj else func_node.attr
    if isinstance(func_node, ast.Name):
        return func_node.id
    return ""


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


@register_rule("MCS-R004", LifecyclePhase.RUNTIME, Severity.HIGH, "Unauthorized Access")
class R004UnauthorizedAccess(BaseRule):
    """Detect tools that perform file/path/command operations using unsanitized
    user-supplied parameters without path-traversal guards."""

    requirement_mode = "any"

    RULE_ID = "MCS-R004"
    PHASE = LifecyclePhase.RUNTIME
    DEFAULT_SEVERITY = Severity.HIGH
    TITLE = "Unauthorized Access"

    @property
    def requires_source(self) -> bool:
        return True

    @property
    def requires_manifest(self) -> bool:
        return True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # --- AST analysis: open() / Path() without path validation ---
        for filepath in ctx.source_files:
            try:
                tree = parse_file(filepath)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            for func in ast.walk(tree):
                if not isinstance(func, ast.FunctionDef):
                    continue

                # Find open(var) or Path(var) calls where var is not a literal
                for child in ast.walk(func):
                    if not isinstance(child, ast.Call):
                        continue
                    call_name = _resolve_call_name(child.func)
                    if call_name not in UNRESTRICTED_PATH_FUNCTIONS:
                        continue
                    if not child.args:
                        continue
                    arg_var = _is_variable(child.args[0])
                    if not arg_var:
                        continue  # literal path — less risky

                    if not _has_path_validation(func, arg_var):
                        findings.append(
                            self._make_finding(
                                description=(
                                    f"Function '{func.name}' calls {call_name}({arg_var}) "
                                    f"without a preceding path traversal check "
                                    f"(Path.resolve() + is_relative_to()). "
                                    f"This may allow access outside the intended directory."
                                ),
                                location=Location(
                                    file=filepath,
                                    line=child.lineno,
                                    tool_name=func.name,
                                ),
                                remediation=(
                                    f"Validate '{arg_var}' before use: resolve the path and "
                                    f"verify it stays within a trusted base directory via "
                                    f"Path(arg_var).resolve().is_relative_to(base_dir)."
                                ),
                                owasp=OWASPMapping(
                                    llm_top10=("LLM06",),
                                    agentic_top10=("ASI03",),
                                ),
                            )
                        )

        # --- Manifest analysis: tools advertising unsafe parameter names ---
        for manifest in ctx.manifests:
            for tool in manifest.tools:
                lower_desc = (tool.description or "").lower()
                flagged_params = [
                    kw for kw in MANIFEST_UNSAFE_PARAM_KEYWORDS
                    if kw in lower_desc
                ]
                if flagged_params:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Tool '{tool.name}' on server '{manifest.server_name}' "
                                f"accepts parameters matching: {', '.join(flagged_params)}. "
                                f"Ensure these inputs are validated against path traversal, "
                                f"injection, and privilege escalation."
                            ),
                            location=Location(
                                tool_name=tool.name,
                            ),
                            remediation=(
                                "Add input validation for all path/file/URL/command "
                                "parameters. Restrict file access to a trusted base "
                                "directory and reject suspicious patterns."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM06",),
                                agentic_top10=("ASI03",),
                            ),
                            confidence=Confidence.LOW,
                        )
                    )

        return findings
