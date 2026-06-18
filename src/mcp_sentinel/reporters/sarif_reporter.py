"""SARIF 2.1.0 reporter for GitHub Code Scanning integration."""

from __future__ import annotations
import json
from pathlib import Path
from mcp_sentinel.core.types import ScanResult


def render(result: ScanResult, output_path: Path | None = None) -> str:
    """Render a ScanResult as a SARIF 2.1.0 JSON string."""
    rules = {}
    results = []
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation, "markdown": f"**Fix:** {f.remediation}"},
                "properties": {
                    "security-severity": _severity_to_score(f.severity.value),
                    "tags": ["mcp", "security", f.phase.value],
                },
            }
        loc = {}
        if f.location.file:
            loc["physicalLocation"] = {
                "artifactLocation": {"uri": str(f.location.file)},
                "region": {"startLine": f.location.line or 1},
            }
        results.append({
            "ruleId": f.rule_id,
            "message": {"text": f.description},
            "locations": [loc] if loc else [],
            "level": _severity_to_level(f.severity.value),
            "properties": {
                "owasp_llm": list(f.owasp.llm_top10),
                "owasp_agentic": list(f.owasp.agentic_top10),
                "confidence": f.confidence.value,
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MCP Sentinel",
                    "version": result.sentinel_version,
                    "informationUri": "https://github.com/mcp-sentinel",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    text = json.dumps(sarif, indent=2, ensure_ascii=False)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    return text


def _severity_to_score(severity: str) -> float:
    return {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 2.0, "info": 0.5}.get(severity, 1.0)


def _severity_to_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}.get(severity, "warning")
