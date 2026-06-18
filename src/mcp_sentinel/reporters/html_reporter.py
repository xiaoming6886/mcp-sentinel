"""HTML reporter for MCP Sentinel — Jinja2-based report generation."""

from __future__ import annotations
from pathlib import Path
from mcp_sentinel.core.types import ScanResult

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>MCP Sentinel Report</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:20px;color:#1a1a2e}
h1{border-bottom:3px solid #6c63ff;padding-bottom:8px}
.severity-critical{border-left:4px solid #e74c3c;background:#fdecea;padding:12px;margin:8px 0}
.severity-high{border-left:4px solid #e67e22;background:#fef5e7;padding:12px;margin:8px 0}
.severity-medium{border-left:4px solid #f1c40f;background:#fef9e7;padding:12px;margin:8px 0}
.severity-low{border-left:4px solid #95a5a6;background:#f4f6f7;padding:12px;margin:8px 0}
.severity-info{border-left:4px solid #3498db;background:#eaf2f8;padding:12px;margin:8px 0}
.finding-header{font-weight:bold;margin-bottom:4px}
.finding-meta{font-size:.85em;color:#666}
.remediation{background:#e8f8f5;padding:8px;margin-top:8px;border-radius:4px}
.stats{display:flex;gap:16px;margin:16px 0}
.stat{padding:8px 16px;background:#eee;border-radius:8px;text-align:center}
</style></head>
<body>
<h1>MCP Sentinel Report</h1>
<p>Target: {{result.target}} | Duration: {{result.duration_seconds}}s | v{{result.sentinel_version}}</p>
<div class="stats">
{% for sev, count in result.stats.findings_by_severity.items() %}
<div class="stat"><strong>{{sev.upper()}}</strong><br>{{count}}</div>
{% endfor %}
</div>
{% if not result.findings %}
<p style="color:green;font-size:1.2em">[PASS] No security issues found.</p>
{% endif %}
{% for f in result.findings %}
<div class="severity-{{f.severity.value}}">
<div class="finding-header">[{{f.severity.value.upper()}}] {{f.rule_id}}: {{f.title}}</div>
<div class="finding-meta">Phase: {{f.phase.value}} | Location: {{f.location}} | Confidence: {{f.confidence.value}}</div>
<p>{{f.description}}</p>
{% if f.remediation %}
<div class="remediation"><strong>Fix:</strong> {{f.remediation}}</div>
{% endif %}
{% if f.owasp.llm_top10 %}<div class="finding-meta">OWASP: {{f.owasp.llm_top10|join(', ')}}</div>{% endif %}
</div>
{% endfor %}
<p><em>Generated {{result.timestamp}}</em></p>
</body></html>"""


def render(result: ScanResult, output_path: Path | None = None) -> str:
    """Render a ScanResult as an HTML report string."""
    try:
        from jinja2 import Template
        tpl = Template(_HTML_TEMPLATE)
        html = tpl.render(result=result)
    except ImportError:
        html = f"<html><body><pre>Requires jinja2. Findings: {len(result.findings)}</pre></body></html>"
    if output_path:
        output_path.write_text(html, encoding="utf-8")
    return html
