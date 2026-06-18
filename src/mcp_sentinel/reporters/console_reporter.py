"""Rich-based console reporter for MCP Sentinel scan results."""

from __future__ import annotations
from mcp_sentinel.core.types import Finding, ScanResult


SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "blue",
}


def render(result: ScanResult) -> str:
    """Render a ScanResult to a Rich-formatted console string.

    Returns a string suitable for printing to console.
    """
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append(f"╔══ MCP Sentinel v{result.sentinel_version} ══╗")
    lines.append(f"║ Target : {result.target}")
    lines.append(f"║ Mode   : {result.scan_mode}")
    lines.append(f"║ Duration: {result.duration_seconds:.2f}s")
    lines.append(f"║ Files  : {result.stats.files_scanned}")
    lines.append(f"║ Tools  : {result.stats.tools_inspected}")
    lines.append(f"║ Rules  : {result.stats.rules_executed}")
    lines.append("╚══════════════════════════╝")
    lines.append("")

    # Findings by severity
    if not result.findings:
        lines.append("[PASS] No security issues found.")
        return "\n".join(lines)

    sev_counts = result.stats.findings_by_severity
    lines.append(f"Findings: {len(result.findings)} "
                 f"(C:{sev_counts['critical']} H:{sev_counts['high']} "
                 f"M:{sev_counts['medium']} L:{sev_counts['low']} I:{sev_counts['info']})")
    lines.append("")

    # Per-finding output
    for i, f in enumerate(result.findings, 1):
        tag = f"[{f.severity.value.upper()}]"
        lines.append(f"--- Finding #{i} {tag} [{f.rule_id}] {f.title} ---")
        lines.append(f"  Phase     : {f.phase.value}")
        lines.append(f"  Location  : {f.location}")
        lines.append(f"  Confidence: {f.confidence.value}")
        lines.append(f"  Description: {f.description}")
        if f.owasp.llm_top10:
            lines.append(f"  OWASP LLM : {', '.join(f.owasp.llm_top10)}")
        if f.owasp.agentic_top10:
            lines.append(f"  OWASP Agent: {', '.join(f.owasp.agentic_top10)}")
        lines.append(f"  Fix       : {f.remediation}")
        lines.append("")

    lines.append(f"Scan complete. {len(result.findings)} finding(s).")
    return "\n".join(lines)
