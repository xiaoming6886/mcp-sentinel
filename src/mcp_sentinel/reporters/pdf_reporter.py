"""PDF reporter for MCP Sentinel — weasyprint HTML→PDF conversion."""

from __future__ import annotations
from pathlib import Path
from mcp_sentinel.core.types import ScanResult
from mcp_sentinel.reporters.html_reporter import render as html_render


def render(result: ScanResult, output_path: Path | None = None) -> str:
    """Render a ScanResult as PDF, using weasyprint to convert HTML."""
    html = html_render(result)
    if not output_path:
        return html  # Fallback: return HTML if no output path
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(str(output_path))
        return f"PDF written to {output_path}"
    except ImportError:
        # Fallback: save HTML with .html extension
        alt = output_path.with_suffix(".html")
        alt.write_text(html, encoding="utf-8")
        return f"weasyprint not available. HTML saved to {alt}"
    except Exception as e:
        return f"PDF generation failed: {e}"
