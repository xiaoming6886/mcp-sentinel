"""JSON reporter for MCP Sentinel — machine-readable scan output."""

from __future__ import annotations
import json
from pathlib import Path
from mcp_sentinel.core.types import ScanResult


def render(result: ScanResult, output_path: Path | None = None) -> str:
    """Render a ScanResult as formatted JSON string.

    If output_path is provided, writes to file.
    Returns the JSON string.
    """
    data = {
        "target": result.target,
        "scan_mode": result.scan_mode,
        "sentinel_version": result.sentinel_version,
        "timestamp": result.timestamp,
        "duration_seconds": result.duration_seconds,
        "stats": {
            "files_scanned": result.stats.files_scanned,
            "tools_inspected": result.stats.tools_inspected,
            "rules_executed": result.stats.rules_executed,
            "findings_by_severity": dict(result.stats.findings_by_severity),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "phase": f.phase.value,
                "location": str(f.location),
                "remediation": f.remediation,
                "owasp_llm_top10": list(f.owasp.llm_top10) if f.owasp.llm_top10 else [],
                "owasp_agentic_top10": list(f.owasp.agentic_top10) if f.owasp.agentic_top10 else [],
                "references": f.references,
            }
            for f in result.findings
        ],
    }
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    return text
