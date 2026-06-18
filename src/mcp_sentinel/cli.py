"""Typer CLI for MCP Sentinel — the MCP security scanner."""

from __future__ import annotations
import sys
from pathlib import Path
import json

import typer

from mcp_sentinel import __version__
from mcp_sentinel.config import OUTPUT_FORMATS, PHASE_MAP, SEVERITY_MAP
from mcp_sentinel.core.engine import ScanEngine
from mcp_sentinel.core.registry import RuleRegistry
from mcp_sentinel.core.types import ScanTarget, Severity, LifecyclePhase
from mcp_sentinel.reporters import console_reporter

app = typer.Typer(
    name="mcp-sentinel",
    help="MCP Sentinel — Security scanner for MCP servers",
    add_completion=False,
)


def _resolve_target(path_str: str) -> str:
    """Resolve a target path, returning absolute path if it exists."""
    p = Path(path_str)
    if p.exists():
        return str(p.resolve())
    return path_str


@app.command()
def scan(
    target: str = typer.Argument(..., help="MCP server path or URI to scan"),
    phase: str = typer.Option(None, help="Filter by lifecycle phase"),
    severity: str = typer.Option("low", help="Minimum severity to report"),
    output: str = typer.Option("console", "-o", help=f"Output format: {', '.join(OUTPUT_FORMATS)}"),
    output_file: Path = typer.Option(None, "-f", help="Write output to file"),
    fail_on: str = typer.Option("high", help="Exit code 1 if findings >= this severity"),
    rules: str = typer.Option(None, help="Comma-separated rule IDs to run"),
    exclude_rules: str = typer.Option(None, help="Comma-separated rule IDs to skip"),
    baseline: Path = typer.Option(None, help="Baseline file for comparison"),
):
    """Scan an MCP server for security threats."""
    target_path = _resolve_target(target)
    if not Path(target_path).exists() and not target.startswith(("http", "stdio:")):
        typer.echo(f"Error: target not found: {target}", err=True)
        raise typer.Exit(code=1)

    if output not in OUTPUT_FORMATS:
        typer.echo(f"Error: invalid output format '{output}'. Choose from: {', '.join(OUTPUT_FORMATS)}", err=True)
        raise typer.Exit(code=1)

    phase_filter = PHASE_MAP.get(phase) if phase else None
    severity_filter = SEVERITY_MAP.get(severity, Severity.LOW)
    fail_on_sev = SEVERITY_MAP.get(fail_on, Severity.HIGH)

    target_obj = ScanTarget(
        path=target_path,
        phase_filter=phase_filter,
        severity_filter=severity_filter,
        output_format=output,
        output_file=output_file,
        fail_on=fail_on_sev,
        baseline_path=baseline,
    )

    engine = ScanEngine()
    rule_list = [r.strip() for r in rules.split(",") if r.strip()] if rules else None
    exclude_list = [r.strip() for r in exclude_rules.split(",") if r.strip()] if exclude_rules else None
    result = engine.run(target_obj, rule_ids=rule_list, exclude_ids=exclude_list)

    # Output
    if output == "console":
        rendered = console_reporter.render(result)
        _write_output(rendered, output_file)
    elif output == "json":
        from mcp_sentinel.reporters.json_reporter import render as json_render
        text = json_render(result, output_file)
        _write_output(text, output_file)
    elif output == "html":
        from mcp_sentinel.reporters.html_reporter import render as html_render
        html_render(result, output_file)
    elif output == "pdf":
        from mcp_sentinel.reporters.pdf_reporter import render as pdf_render
        pdf_render(result, output_file)
    elif output == "sarif":
        from mcp_sentinel.reporters.sarif_reporter import render as sarif_render
        sarif_render(result, output_file)

    # Exit code based on fail-on threshold
    exit_code = engine.compute_exit_code(result, fail_on)
    raise typer.Exit(code=exit_code)


@app.command()
def baseline(
    target: str = typer.Argument(..., help="MCP server to create baseline for"),
    output_file: Path = typer.Option(Path("baseline.json"), "-o", help="Baseline output file"),
):
    """Create a baseline snapshot of an MCP server's security posture."""
    target_path = _resolve_target(target)
    engine = ScanEngine()
    target_obj = ScanTarget(path=target_path)
    result = engine.run(target_obj)

    data = _to_json(result)
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    output_file.write_text(text, encoding="utf-8")
    typer.echo(f"Baseline saved to {output_file}")


@app.command()
def diff(
    baseline_file: Path = typer.Argument(..., help="Baseline JSON file"),
    target: str = typer.Argument(..., help="MCP server to compare"),
):
    """Compare current scan against a baseline snapshot."""
    if not baseline_file.exists():
        typer.echo(f"Error: baseline file not found: {baseline_file}", err=True)
        raise typer.Exit(code=1)

    baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
    target_path = _resolve_target(target)
    engine = ScanEngine()
    target_obj = ScanTarget(path=target_path)
    result = engine.run(target_obj)
    current_data = _to_json(result)

    baseline_ids = {f["rule_id"]: f for f in baseline_data.get("findings", [])}
    current_ids = {f["rule_id"]: f for f in current_data.get("findings", [])}

    new = [f for rid, f in current_ids.items() if rid not in baseline_ids]
    eliminated = [f for rid, f in baseline_ids.items() if rid not in current_ids]
    changed = []
    for rid in (baseline_ids.keys() & current_ids.keys()):
        b = baseline_ids[rid]
        c = current_ids[rid]
        if b.get("severity") != c.get("severity"):
            changed.append({"rule_id": rid, "from": b.get("severity"), "to": c.get("severity")})

    typer.echo(f"Baseline: {len(baseline_data.get('findings', []))} findings")
    typer.echo(f"Current : {len(current_data.get('findings', []))} findings")
    typer.echo(f"New     : {len(new)}")
    typer.echo(f"Eliminated: {len(eliminated)}")
    typer.echo(f"Changed : {len(changed)}")

    if new:
        typer.echo("\n--- New Findings ---")
        for f in new:
            typer.echo(f"  [{f.get('severity', '?').upper()}] [{f['rule_id']}] {f.get('title', '')}")
    if changed:
        typer.echo("\n--- Severity Changes ---")
        for c in changed:
            typer.echo(f"  [{c['rule_id']}] {c['from']} → {c['to']}")


@app.command()
def list_rules():
    """List all available detection rules."""
    rules = RuleRegistry.get_all()
    if not rules:
        typer.echo("No rules registered.")
        return
    for rid, cls in sorted(rules.items()):
        typer.echo(f"[{cls.PHASE.value}] {rid}: {cls.TITLE}")


@app.command()
def version():
    """Show version information."""
    typer.echo(f"MCP Sentinel v{__version__}")


def _write_output(text: str, output_file: Path | None) -> None:
    if output_file:
        output_file.write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


def _to_json(result) -> dict:
    """Convert ScanResult to JSON-serializable dict."""
    return {
        "target": result.target,
        "version": result.sentinel_version,
        "timestamp": result.timestamp,
        "duration_seconds": result.duration_seconds,
        "stats": {
            "files_scanned": result.stats.files_scanned,
            "tools_inspected": result.stats.tools_inspected,
            "rules_executed": result.stats.rules_executed,
            "findings_by_severity": result.stats.findings_by_severity,
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
            }
            for f in result.findings
        ],
    }
