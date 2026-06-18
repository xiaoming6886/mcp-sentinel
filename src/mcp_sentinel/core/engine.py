"""ScanEngine — core orchestration for MCP Sentinel scans."""

from __future__ import annotations
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from mcp_sentinel.core.context import build_context
from mcp_sentinel.core.registry import RuleRegistry

# Ensure all rules are registered before any scan
import mcp_sentinel.rules  # noqa: F401 — triggers @register_rule decorators
from mcp_sentinel.core.types import Finding, ScanResult, ScanStats, ScanTarget
from mcp_sentinel.utils.owasp import get_owasp_mapping
from mcp_sentinel import __version__


class ScanEngine:
    """Orchestrates the full scan pipeline: connector→context→rules→report."""

    def __init__(self, max_workers: int = 4):
        self._max_workers = max_workers

    def run(self, target: ScanTarget, rule_ids: list[str] | None = None, exclude_ids: list[str] | None = None) -> ScanResult:
        """Execute a complete scan against the target."""
        start = time.monotonic()

        # Step 1: Build context
        ctx = build_context(target)

        # Step 2: Select applicable rules
        rules = RuleRegistry.get_applicable(
            ctx,
            phase_filter=target.phase_filter,
            rule_ids=rule_ids,
            exclude_ids=exclude_ids,
        )

        # Step 3: Execute rules in parallel
        all_findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {pool.submit(rule.check, ctx): rule for rule in rules}
            for future in as_completed(futures):
                findings = future.result()
                all_findings.extend(findings)

        # Step 4: Post-process
        # Deduplicate
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in all_findings:
            key = (f.rule_id, str(f.location))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Sort by severity (critical first)
        severities = ["critical", "high", "medium", "low", "info"]
        unique.sort(key=lambda f: (
            severities.index(f.severity.value) if f.severity.value in severities else 99,
            str(f.location.file or ""),
            f.location.line or 0,
        ))

        # OWASP enrichment: attach mapping to each finding
        for f in unique:
            if not f.owasp.llm_top10 and not f.owasp.agentic_top10:
                f.owasp = get_owasp_mapping(f.rule_id)

        # Step 5: Apply severity filter (BEFORE stats)
        severities = ["info", "low", "medium", "high", "critical"]
        threshold_idx = severities.index(target.severity_filter.value)
        unique = [f for f in unique if severities.index(f.severity.value) >= threshold_idx]

        # Step 6: Compute statistics
        stats = self._compute_stats(ctx, rules, unique)

        duration = time.monotonic() - start

        return ScanResult(
            target=target.path,
            scan_mode=target.mode,
            findings=unique,
            stats=stats,
            duration_seconds=round(duration, 3),
            sentinel_version=__version__,
        )

    def compute_exit_code(self, result: ScanResult, fail_on: str = "high") -> int:
        """Determine exit code based on --fail-on threshold.

        Returns 1 if any finding meets or exceeds the threshold, 0 otherwise.
        """
        severities = ["info", "low", "medium", "high", "critical"]
        threshold_idx = severities.index(fail_on.lower()) if fail_on.lower() in severities else 3
        for f in result.findings:
            finding_idx = severities.index(f.severity.value) if f.severity.value in severities else 0
            if finding_idx >= threshold_idx:
                return 1
        return 0

    @staticmethod
    def _compute_stats(ctx, rules, findings) -> ScanStats:
        stats = ScanStats()
        stats.files_scanned = len(ctx.source_files)
        stats.tools_inspected = (
            len(ctx.manifest.tools) if ctx.manifest else 0
        )
        stats.rules_executed = len(rules)
        for f in findings:
            sev = f.severity.value
            if sev in stats.findings_by_severity:
                stats.findings_by_severity[sev] += 1
        return stats
