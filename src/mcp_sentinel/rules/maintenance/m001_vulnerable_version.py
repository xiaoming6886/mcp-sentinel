"""MCS-M001: Vulnerable Version — audit Python dependency files for
unpinned and known-vulnerable package versions."""

from __future__ import annotations

import re
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Known-vulnerable package constraints: (package_name, max_fixed_version, cve_ref)
# Flagged when installed version is STRICTLY less than the fixed version.
# ---------------------------------------------------------------------------

_KNOWN_VULNERABLE: list[tuple[str, str, str]] = [
    ("pyyaml", "6.0", "CVE-2020-14343 / CVE-2017-18342"),
    ("requests", "2.32.0", "CVE-2024-35195 / CVE-2023-32681"),
    ("cryptography", "42.0.0", "CVE-2023-50782 / CVE-2023-49083"),
    ("urllib3", "2.0.0", "CVE-2023-45803 / CVE-2023-43804"),
    ("jinja2", "3.1.3", "CVE-2024-22195 / CVE-2024-34064"),
]

# ---------------------------------------------------------------------------
# Line parsers
# ---------------------------------------------------------------------------

# requirements.txt: package==version  or  package>=version  or  package
_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_\-\.]+)"
    r"\s*(?P<op>[><=!~]+)?\s*"
    r"(?P<version>[A-Za-z0-9\.\*\+_\-]+)?"
)

# pyproject.toml dependency spec: "package>=version" or "package==version"
_TOML_DEP_RE = re.compile(
    r"""['\"](?P<name>[A-Za-z0-9_\-\.]+)['\"]\s*:\s*['\"]  # "name": "
        (?P<spec>.+?)['\"]""",
    re.VERBOSE,
)


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse a version string into a comparable tuple. Returns None on failure."""
    try:
        return tuple(int(p) for p in version_str.split(".") if p.isdigit())
    except (ValueError, AttributeError):
        return None


@register_rule("MCS-M001", LifecyclePhase.MAINTENANCE, Severity.MEDIUM, "Vulnerable Version")
class VulnerableVersionRule(BaseRule):
    """Audit requirements.txt and pyproject.toml for risky dependency versions."""

    requires_source = True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        target_root = Path(ctx.target.path)
        if not target_root.is_dir():
            target_root = target_root.parent

        # Locate dependency files
        dep_files = list(target_root.rglob("requirements*.txt")) + list(
            target_root.rglob("pyproject.toml")
        )

        for dep_file in dep_files:
            if dep_file.name.endswith(".txt"):
                findings.extend(self._scan_requirements_txt(dep_file))
            elif dep_file.name == "pyproject.toml":
                findings.extend(self._scan_pyproject_toml(dep_file))

        return findings

    # ------------------------------------------------------------------
    # requirements.txt scanner
    # ------------------------------------------------------------------

    def _scan_requirements_txt(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Skip options like -r, -e, --index-url
            if stripped.startswith("-"):
                continue

            match = _REQ_LINE_RE.match(stripped)
            if not match:
                continue

            name = match.group("name")
            op = match.group("op") or ""
            version = match.group("version") or ""

            if not name:
                continue

            # --- Check 1: Unpinned dependency (LOW) ---
            if not op or op == ">" or op == ">=":
                if not version:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Unpinned dependency '{name}' in "
                                f"{path.name}:{idx} — no version constraint specified"
                            ),
                            location=Location(
                                file=path, line=idx, snippet=stripped[:200]
                            ),
                            remediation=(
                                f"Pin '{name}' to a specific version (e.g., "
                                f"'{name}==X.Y.Z') for reproducible builds."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM03",),
                                agentic_top10=("ASI04",),
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                        )
                    )

            # --- Check 2: Known-vulnerable package (MEDIUM) ---
            for vuln_name, fixed_ver, cve_ref in _KNOWN_VULNERABLE:
                if name.lower().replace("_", "-") != vuln_name.lower().replace("_", "-"):
                    continue

                if not version:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"'{name}' in {path.name}:{idx} has no version pinned — "
                                f"may include vulnerable versions ({cve_ref}). "
                                f"Fixed in >={fixed_ver}"
                            ),
                            location=Location(
                                file=path, line=idx, snippet=stripped[:200]
                            ),
                            remediation=(
                                f"Pin '{name}>={fixed_ver}' to ensure you have the "
                                f"patched version. Run 'pip install --upgrade {name}'."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM03",),
                                agentic_top10=("ASI04",),
                            ),
                            confidence=Confidence.HIGH,
                            metadata={"cve": cve_ref},
                        )
                    )
                    continue

                # Parse the installed version and compare
                installed = _parse_version(version)
                fixed = _parse_version(fixed_ver)
                if installed and fixed and installed < fixed:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"'{name}=={version}' in {path.name}:{idx} is vulnerable "
                                f"({cve_ref}). Fixed in >={fixed_ver}"
                            ),
                            location=Location(
                                file=path, line=idx, snippet=stripped[:200]
                            ),
                            remediation=(
                                f"Upgrade '{name}' to >={fixed_ver}. "
                                f"Run: pip install --upgrade '{name}>={fixed_ver}'"
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM03",),
                                agentic_top10=("ASI04",),
                            ),
                            confidence=Confidence.HIGH,
                            metadata={"cve": cve_ref, "current": version, "fixed": fixed_ver},
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # pyproject.toml scanner
    # ------------------------------------------------------------------

    def _scan_pyproject_toml(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        lines = content.splitlines()

        # Find dependency sections
        in_deps = False
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Detect section headers
            if re.match(r"^\[project\]", stripped):
                in_deps = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_deps = stripped.startswith("[project.optional-dependencies]")

            if not in_deps:
                continue

            # Match "package": "^version" or "package": ">=version"
            toml_match = re.search(
                r"""['\"](?P<name>[A-Za-z0-9_\-\.]+)['\"]\s*:\s*['\"]
                    [\^~><=]?\s*(?P<version>[A-Za-z0-9\.\*]+)['\"]""",
                stripped,
                re.VERBOSE,
            )
            if not toml_match:
                continue

            name = toml_match.group("name")
            version = toml_match.group("version")

            for vuln_name, fixed_ver, cve_ref in _KNOWN_VULNERABLE:
                if name.lower().replace("_", "-") != vuln_name.lower().replace("_", "-"):
                    continue

                installed = _parse_version(version)
                fixed = _parse_version(fixed_ver)
                if installed and fixed and installed < fixed:
                    findings.append(
                        self._make_finding(
                            description=(
                                f"'{name}=={version}' in {path.name}:{idx} is vulnerable "
                                f"({cve_ref}). Fixed in >={fixed_ver}"
                            ),
                            location=Location(
                                file=path, line=idx, snippet=stripped[:200]
                            ),
                            remediation=(
                                f"Upgrade '{name}' to >={fixed_ver} in pyproject.toml "
                                f"and re-lock dependencies."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM03",),
                                agentic_top10=("ASI04",),
                            ),
                            confidence=Confidence.HIGH,
                            metadata={"cve": cve_ref, "current": version, "fixed": fixed_ver},
                        )
                    )

        return findings
