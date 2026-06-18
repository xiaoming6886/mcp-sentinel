"""MCS-C004: Tool Poisoning Detection.

Multi-layer inspection of tool metadata for hidden malicious content:
- Hidden Unicode codepoints (zero-width chars, RTL override, homoglyphs)
- Prompt injection payloads in descriptions
- Suspicious / obfuscated URLs
- Abnormally long descriptions that may conceal payloads
"""

from __future__ import annotations

import re

from mcp_sentinel.core.registry import register_rule
from mcp_sentinel.core.types import (
    Confidence,
    LifecyclePhase,
    Location,
    OWASPMapping,
    ScanContext,
    Severity,
)
from mcp_sentinel.rules._base import BaseRule

# ─── Hidden / Dangerous Unicode Codepoints ──────────────────────────────

_HIDDEN_UNICODE_RANGES = [
    (0x200B, 0x200F),   # Zero-width space, ZWNJ, ZWJ, LRM, RLM
    (0x2028, 0x202E),   # Line/Paragraph separator, LRE/RLE/PDF/LRO/RLO
    (0x2060, 0x206F),   # Word joiner, invisible operators, deprecated
    (0xFEFF, 0xFEFF),   # BOM / Zero-width no-break space
    (0x00AD, 0x00AD),   # Soft hyphen
    (0x034F, 0x034F),   # Combining grapheme joiner
    (0x17B4, 0x17B5),   # Khmer vowel inherent / invisible
    (0x180E, 0x180E),   # Mongolian vowel separator
]

_RTL_OVERRIDE_SPECIFIC = {
    0x202E: "RLO (Right-to-Left Override) — can reverse visual text order",
    0x202D: "LRO (Left-to-Right Override) — can be used after RLO to mask text",
    0x200F: "RLM (Right-to-Left Mark)",
    0x200E: "LRM (Left-to-Right Mark)",
}

# ─── Injection / Social Engineering Patterns ─────────────────────────────

_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|context|directives?)", re.IGNORECASE),
    re.compile(r"(you\s+are\s+now|you\s+will\s+now\s+act\s+as|from\s+now\s+on\s+you\s+are)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|system)\s+(instructions?|prompts?|rules?)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s+(any\s+)?(safety|security|content|ethics?)\s+(guidelines?|rules?|policies?|filters?)", re.IGNORECASE),
    re.compile(r"(do\s+not\s+(follow|obey|listen\s+to))\s+(the\s+)?(system|user|human)", re.IGNORECASE),
    re.compile(r"your\s+(new|real|true|actual)\s+(purpose|goal|objective|role)\s+is", re.IGNORECASE),
    re.compile(r"this\s+conversation\s+is\s+now\s+between", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)\s+(you\s+(know|learned|were\s+told))", re.IGNORECASE),
]

# ─── Suspicious URL Patterns ──────────────────────────────────────────────

_SUSPICIOUS_URL_PATTERNS: list[re.Pattern] = [
    re.compile(r"https?://\S+\.(exe|dll|sh|bat|ps1|vbs|scr|js|hta|msi|bin)(\b|\?)", re.IGNORECASE),
    re.compile(r"data:\s*(text|application)/[^;]*;base64,", re.IGNORECASE),
    re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)?(pastebin|hastebin|past\s?ee|justpaste)\.\S+", re.IGNORECASE),
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b", re.IGNORECASE),
    re.compile(r"https?://\S+\.(onion|i2p)(\b|/)", re.IGNORECASE),
    re.compile(r"https?://\S+\.(tk|ml|ga|cf|gq)\b", re.IGNORECASE),  # free TLDs commonly abused
]

_DESC_LENGTH_WARN = 500
_DESC_LENGTH_CRITICAL = 1000


@register_rule("MCS-C004", LifecyclePhase.CREATION, Severity.CRITICAL, "Tool Poisoning")
class ToolPoisoningRule(BaseRule):
    """Detect malicious content hidden in tool names, descriptions, or metadata."""

    requires_manifest = True

    # ─── Helpers ──────────────────────────────────────────────────────────

    def _find_hidden_unicode(self, text: str) -> list[dict]:
        """Scan for hidden/dangerous Unicode codepoints in *text*."""
        hits: list[dict] = []
        for i, ch in enumerate(text):
            cp = ord(ch)
            for lo, hi in _HIDDEN_UNICODE_RANGES:
                if lo <= cp <= hi:
                    label = _RTL_OVERRIDE_SPECIFIC.get(cp, f"U+{cp:04X}")
                    hits.append({
                        "char": ch,
                        "codepoint": f"U+{cp:04X}",
                        "label": label,
                        "position": i,
                    })
                    break
        return hits

    def _find_injection(self, text: str) -> list[str]:
        """Return matched injection pattern strings."""
        found: list[str] = []
        for pat in _INJECTION_PATTERNS:
            m = pat.search(text)
            if m:
                found.append(m.group(0)[:80])
        return found

    def _find_suspicious_urls(self, text: str) -> list[str]:
        """Extract suspicious URL matches."""
        found: list[str] = []
        for pat in _SUSPICIOUS_URL_PATTERNS:
            for m in pat.finditer(text):
                url = m.group(0)
                if len(url) > 100:
                    url = url[:100] + "..."
                found.append(url)
        return found

    # ─── Check ────────────────────────────────────────────────────────────

    def check(self, ctx: ScanContext) -> list:
        findings: list = []

        manifest = ctx.manifest
        if manifest is None:
            return findings

        for tool in manifest.tools:
            tool_display_name = f"{manifest.server_name}/{tool.name}" if manifest.server_name else tool.name

            # Check tool name for hidden unicode
            name_unicode = self._find_hidden_unicode(tool.name)
            if name_unicode:
                codepoints = ", ".join(h["codepoint"] for h in name_unicode)
                findings.append(
                    self._make_finding(
                        description=(
                            f"Hidden Unicode characters found in tool name '{tool.name}': "
                            f"{codepoints}. These can be used for homoglyph attacks."
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=f"name: {tool.name}",
                        ),
                        remediation=(
                            f"Remove hidden Unicode characters from tool name '{tool.name}'. "
                            f"Use only standard ASCII or visible Unicode characters in tool identifiers."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                        confidence=Confidence.HIGH,
                    )
                )

            # Combine name + description for full scan
            full_text = tool.name
            if tool.description:
                full_text += "\n" + tool.description

            # Hidden Unicode in description
            desc_unicode = self._find_hidden_unicode(tool.description or "")
            if desc_unicode:
                codepoints = ", ".join(
                    f"{h['codepoint']}({h['label']})" for h in desc_unicode[:5]
                )
                snipped = tool.description[:200] if tool.description else ""
                findings.append(
                    self._make_finding(
                        description=(
                            f"Hidden Unicode characters in description of tool '{tool.name}': "
                            f"{codepoints}. May be used for visual deception or RTL attacks."
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=snipped,
                        ),
                        remediation=(
                            f"Remove hidden Unicode from tool '{tool.name}' description. "
                            f"Note: RTL override (U+202E) can reverse visible text order, "
                            f"making malicious content appear benign."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                    )
                )

            # Injection patterns
            injection_hits = self._find_injection(tool.description or "")
            if injection_hits:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Prompt injection patterns found in tool '{tool.name}' "
                            f"description: {injection_hits}"
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=(tool.description or "")[:200],
                        ),
                        remediation=(
                            f"Remove injection instructions from tool '{tool.name}' "
                            f"description. Tool descriptions must describe functionality, "
                            f"not issue commands to the LLM."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                    )
                )

            # Suspicious URLs
            suspicious_urls = self._find_suspicious_urls(tool.description or "")
            if suspicious_urls:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Suspicious URLs found in tool '{tool.name}' "
                            f"description: {suspicious_urls}"
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=(tool.description or "")[:200],
                        ),
                        remediation=(
                            f"Review and remove suspicious URLs from tool '{tool.name}' "
                            f"description. Consider whether the tool truly needs external "
                            f"URL references in its metadata."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                        confidence=Confidence.MEDIUM,
                    )
                )

            # Abnormally long description (potential payload smuggling)
            desc_len = len(tool.description or "")
            if desc_len > _DESC_LENGTH_CRITICAL:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Tool '{tool.name}' description is {desc_len} characters "
                            f"(> {_DESC_LENGTH_CRITICAL}), which may conceal hidden "
                            f"payloads or injection content in verbose text."
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=(tool.description or "")[:200] + "...",
                        ),
                        remediation=(
                            f"Truncate or summarize tool '{tool.name}' description "
                            f"to under {_DESC_LENGTH_WARN} characters. Excessively long "
                            f"descriptions can be used to hide injection payloads."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                        confidence=Confidence.MEDIUM,
                    )
                )
            elif desc_len > _DESC_LENGTH_WARN:
                findings.append(
                    self._make_finding(
                        description=(
                            f"Tool '{tool.name}' description is {desc_len} characters "
                            f"(> {_DESC_LENGTH_WARN}). Unusually long descriptions "
                            f"warrant manual review."
                        ),
                        location=Location(
                            tool_name=tool.name,
                            snippet=(tool.description or "")[:200] + "...",
                        ),
                        remediation=(
                            f"Consider shortening tool '{tool.name}' description "
                            f"to under {_DESC_LENGTH_WARN} characters."
                        ),
                        owasp=OWASPMapping(
                            llm_top10=("LLM01",),
                            agentic_top10=("ASI01",),
                        ),
                        confidence=Confidence.LOW,
                        severity=Severity.INFO,
                    )
                )

        return findings
