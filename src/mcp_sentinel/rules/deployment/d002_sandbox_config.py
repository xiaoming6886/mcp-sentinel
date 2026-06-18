"""MCS-D002: Sandbox Configuration — detect insecure Docker container settings
that weaken isolation or grant excessive host privileges."""

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
# Patterns for Dockerfile checks
# ---------------------------------------------------------------------------

_DOCKERFILE_PRIVILEGED_RE = re.compile(
    r"(?:RUN|CMD|ENTRYPOINT)\s+.*--privileged",
    re.IGNORECASE,
)

_DOCKERFILE_USER_ROOT_RE = re.compile(
    r"^\s*USER\s+root\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_DOCKERFILE_CAP_ADD_RE = re.compile(
    r"--cap-add\s*=\s*(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|SYS_RAWIO)",
    re.IGNORECASE,
)

# Additional risky Dockerfile patterns
_DOCKERFILE_RISKY_FLAGS = [
    (re.compile(r"--network\s*=\s*host", re.IGNORECASE), "network=host"),
    (re.compile(r"--pid\s*=\s*host", re.IGNORECASE), "pid=host"),
    (re.compile(r"--ipc\s*=\s*host", re.IGNORECASE), "ipc=host"),
    (re.compile(r"--security-opt\s+seccomp\s*=\s*unconfined", re.IGNORECASE), "seccomp=unconfined"),
    (re.compile(r"--security-opt\s+apparmor\s*=\s*unconfined", re.IGNORECASE), "apparmor=unconfined"),
]

_DOCKERFILE_NAME_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile")


# ---------------------------------------------------------------------------
# Patterns for docker-compose.yml checks
# ---------------------------------------------------------------------------

_COMPOSE_PRIVILEGED_RE = re.compile(
    r"privileged\s*:\s*true",
    re.IGNORECASE,
)

_COMPOSE_NETWORK_HOST_RE = re.compile(
    r"network_mode\s*:\s*(?:host|\"host\"|'host')",
    re.IGNORECASE,
)

_COMPOSE_PID_HOST_RE = re.compile(
    r"pid\s*:\s*(?:host|\"host\"|'host')",
    re.IGNORECASE,
)

# Excessive volume mounts: binding host root or sensitive paths
_COMPOSE_SENSITIVE_VOLUME_RE = re.compile(
    r"-\s*(?:/etc|/var/run|/proc|/sys|/root|/home|/tmp|C:\\)"
    r"\S*\s*:\s*\S+",
    re.IGNORECASE,
)


def _match_dockerfile_name(name: str) -> bool:
    """Check if a filename looks like a Dockerfile."""
    lower = name.lower()
    if lower == "dockerfile":
        return True
    if lower.startswith("dockerfile."):
        return True
    if lower.endswith(".dockerfile"):
        return True
    return False


def _match_compose_name(name: str) -> bool:
    """Check if a filename looks like a docker-compose file."""
    lower = name.lower()
    return any(
        lower == candidate
        for candidate in (
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        )
    )


@register_rule("MCS-D002", LifecyclePhase.DEPLOYMENT, Severity.HIGH, "Sandbox Configuration")
class SandboxConfigRule(BaseRule):
    """Detect Dockerfile and compose files that weaken container isolation."""

    requires_source = True

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        target_root = Path(ctx.target.path)
        if not target_root.is_dir():
            target_root = target_root.parent

        # Collect Dockerfile(s) and compose file(s)
        dockerfiles: list[Path] = []
        compose_files: list[Path] = []

        for fpath in target_root.rglob("*"):
            if fpath.is_file():
                name = fpath.name
                if _match_dockerfile_name(name):
                    dockerfiles.append(fpath)
                elif _match_compose_name(name):
                    compose_files.append(fpath)

        # Scan Dockerfiles
        for df_path in dockerfiles:
            findings.extend(self._scan_dockerfile(df_path))

        # Scan docker-compose files
        for cf_path in compose_files:
            findings.extend(self._scan_compose_file(cf_path))

        return findings

    # ------------------------------------------------------------------
    # Dockerfile scanning
    # ------------------------------------------------------------------

    def _scan_dockerfile(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        lines = content.splitlines()

        # 1. --privileged flag
        for idx, line in enumerate(lines, start=1):
            if _DOCKERFILE_PRIVILEGED_RE.search(line):
                findings.append(
                    self._make_finding(
                        description=(
                            f"Dockerfile '{path.name}:{idx}' uses --privileged flag, "
                            f"granting the container all host capabilities"
                        ),
                        location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                        remediation=(
                            "Remove --privileged. Instead, use --cap-add only for the "
                            "specific capabilities the container actually needs."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI05",),
                        ),
                    )
                )

        # 2. USER root
        for m in _DOCKERFILE_USER_ROOT_RE.finditer(content):
            line_no = content[: m.start()].count("\n") + 1
            findings.append(
                self._make_finding(
                    description=(
                        f"Dockerfile '{path.name}:{line_no}' runs as USER root — "
                        f"container processes have full root privileges"
                    ),
                    location=Location(file=path, line=line_no, snippet=m.group().strip()),
                    remediation=(
                        "Create a non-root user in the Dockerfile and switch to it "
                        "with 'USER <nonroot>' before running the application."
                    ),
                    owasp=OWASPMapping(
                        llm_top10=("LLM06",),
                        agentic_top10=("ASI05",),
                    ),
                )
            )

        # 3. --cap-add dangerous flags
        for idx, line in enumerate(lines, start=1):
            if _DOCKERFILE_CAP_ADD_RE.search(line):
                findings.append(
                    self._make_finding(
                        description=(
                            f"Dockerfile '{path.name}:{idx}' adds dangerous capability "
                            f"— excessive kernel access granted"
                        ),
                        location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                        remediation=(
                            "Avoid --cap-add=SYS_ADMIN or --cap-add=ALL. Grant only "
                            "the minimal capabilities required (e.g., NET_BIND_SERVICE)."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI05",),
                        ),
                    )
                )

        # 4. Other risky flags (network=host, pid=host, seccomp unconfined, etc.)
        for idx, line in enumerate(lines, start=1):
            for pattern_re, flag_desc in _DOCKERFILE_RISKY_FLAGS:
                if pattern_re.search(line):
                    findings.append(
                        self._make_finding(
                            description=(
                                f"Dockerfile '{path.name}:{idx}' uses risky flag "
                                f"'{flag_desc}' — weakens container isolation"
                            ),
                            location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                            remediation=(
                                f"Remove --{flag_desc}. Use bridge networking and "
                                f"namespace isolation unless host access is strictly required."
                            ),
                            owasp=OWASPMapping(
                                llm_top10=("LLM06",),
                                agentic_top10=("ASI05",),
                            ),
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # docker-compose.yml scanning
    # ------------------------------------------------------------------

    def _scan_compose_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        lines = content.splitlines()

        # 1. privileged: true
        for idx, line in enumerate(lines, start=1):
            if _COMPOSE_PRIVILEGED_RE.search(line):
                findings.append(
                    self._make_finding(
                        description=(
                            f"docker-compose '{path.name}:{idx}' has 'privileged: true' — "
                            f"container runs with all host capabilities"
                        ),
                        location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                        remediation=(
                            "Remove 'privileged: true' and specify only required "
                            "capabilities via 'cap_add'."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI05",),
                        ),
                    )
                )

        # 2. network_mode: host
        for idx, line in enumerate(lines, start=1):
            if _COMPOSE_NETWORK_HOST_RE.search(line):
                findings.append(
                    self._make_finding(
                        description=(
                            f"docker-compose '{path.name}:{idx}' uses 'network_mode: host' — "
                            f"container shares host network namespace"
                        ),
                        location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                        remediation=(
                            "Use bridge or custom overlay networks instead of host "
                            "networking to maintain network isolation."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI05",),
                        ),
                    )
                )

        # 3. pid: host
        for idx, line in enumerate(lines, start=1):
            if _COMPOSE_PID_HOST_RE.search(line):
                findings.append(
                    self._make_finding(
                        description=(
                            f"docker-compose '{path.name}:{idx}' uses 'pid: host' — "
                            f"container can see host processes"
                        ),
                        location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                        remediation=(
                            "Remove 'pid: host' to prevent the container from "
                            "inspecting or signalling host processes."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI05",),
                        ),
                    )
                )

        # 4. Sensitive volume mounts
        for idx, line in enumerate(lines, start=1):
            match = _COMPOSE_SENSITIVE_VOLUME_RE.search(line)
            if match:
                findings.append(
                    self._make_finding(
                        description=(
                            f"docker-compose '{path.name}:{idx}' mounts sensitive host "
                            f"path '{match.group().strip()[:80]}' — potential host escape risk"
                        ),
                        location=Location(file=path, line=idx, snippet=line.strip()[:200]),
                        remediation=(
                            "Avoid bind-mounting sensitive host directories (/etc, "
                            "/var/run, /proc, /sys). Mount only the specific data "
                            "directories the container needs."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM06",),
                            agentic_top10=("ASI05",),
                        ),
                    )
                )

        return findings
