"""Rule registry for MCP Sentinel — decorator-based rule registration."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_sentinel.rules._base import BaseRule
    from mcp_sentinel.core.types import LifecyclePhase, ScanContext

_RULE_REGISTRY: dict[str, type[BaseRule]] = {}


def register_rule(
    rule_id: str,
    phase: "LifecyclePhase",
    severity: "Severity",
    title: str,
):
    """Decorator to register a detection rule with the global registry."""

    def decorator(cls: type[BaseRule]) -> type[BaseRule]:
        cls.RULE_ID = rule_id
        cls.PHASE = phase
        cls.DEFAULT_SEVERITY = severity
        cls.TITLE = title
        _RULE_REGISTRY[rule_id] = cls
        return cls

    return decorator


class RuleRegistry:
    """Singleton registry for all MCP Sentinel detection rules."""

    @staticmethod
    def get_all() -> dict[str, type[BaseRule]]:
        """Return a copy of the complete rule registry."""
        return dict(_RULE_REGISTRY)

    @staticmethod
    def get_by_phase(phase: "LifecyclePhase") -> list[type[BaseRule]]:
        """Return rules filtered by lifecycle phase."""
        return [r for r in _RULE_REGISTRY.values() if r.PHASE == phase]

    @staticmethod
    def get_by_id(rule_id: str) -> type[BaseRule] | None:
        """Look up a single rule by its ID."""
        return _RULE_REGISTRY.get(rule_id)

    @staticmethod
    def get_applicable(
        ctx: "ScanContext",
        phase_filter: "LifecyclePhase | None" = None,
        rule_ids: list[str] | None = None,
        exclude_ids: list[str] | None = None,
    ) -> list[BaseRule]:
        """Return instantiated rules applicable to the given context and filters."""
        rules: list[BaseRule] = []
        for rid, cls in _RULE_REGISTRY.items():
            if phase_filter and cls.PHASE != phase_filter:
                continue
            if rule_ids and rid not in rule_ids:
                continue
            if exclude_ids and rid in exclude_ids:
                continue
            instance = cls()
            # Filter by data requirements
            if instance.requirement_mode == "any":
                # OR logic: include if ANY required data type is available
                needs_source = instance.requires_source and ctx.has_source
                needs_manifest = instance.requires_manifest and ctx.has_manifest
                needs_config = instance.requires_config and ctx.has_config
                required_any = instance.requires_source or instance.requires_manifest or instance.requires_config
                if required_any and not (needs_source or needs_manifest or needs_config):
                    continue
            else:
                # AND logic (default): include only if ALL required data types are available
                if instance.requires_source and not ctx.has_source:
                    continue
                if instance.requires_manifest and not ctx.has_manifest:
                    continue
                if instance.requires_config and not ctx.has_config:
                    continue
            rules.append(instance)
        return rules

    @staticmethod
    def count() -> int:
        """Return the total number of registered rules."""
        return len(_RULE_REGISTRY)
