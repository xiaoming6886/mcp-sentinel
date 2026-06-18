"""OWASP Top 10 mapping constants for MCP Sentinel findings."""

from __future__ import annotations
from mcp_sentinel.core.types import OWASPMapping

# OWASP LLM Top 10 (2025)
LLM01 = "LLM01: Prompt Injection"
LLM02 = "LLM02: Sensitive Information Disclosure"
LLM03 = "LLM03: Supply Chain"
LLM05 = "LLM05: Improper Output Handling"
LLM06 = "LLM06: Excessive Agency"

# OWASP Agentic Top 10
ASI01 = "ASI01: Agent Goal Hijacking"
ASI02 = "ASI02: Tool Misuse"
ASI03 = "ASI03: Identity & Privilege Abuse"
ASI04 = "ASI04: Agentic Supply Chain"
ASI05 = "ASI05: Unexpected Code Execution"
ASI06 = "ASI06: Memory & Context Poisoning"

# Rule → OWASP mapping lookup
RULE_OWASP: dict[str, OWASPMapping] = {
    # Creation phase
    "MCS-C001": OWASPMapping((LLM03,), (ASI04,)),
    "MCS-C002": OWASPMapping((LLM06,), (ASI02,)),
    "MCS-C003": OWASPMapping((LLM01,), (ASI01,)),
    "MCS-C004": OWASPMapping((LLM01,), (ASI01,)),
    "MCS-C005": OWASPMapping((LLM05,), (ASI05,)),
    "MCS-C006": OWASPMapping((LLM03,), (ASI04,)),
    # Deployment phase
    "MCS-D001": OWASPMapping((LLM02,), (ASI03,)),
    "MCS-D002": OWASPMapping((LLM06,), (ASI05,)),
    "MCS-D003": OWASPMapping((LLM03,), (ASI04,)),
    # Runtime phase
    "MCS-R001": OWASPMapping((LLM01,), (ASI06,)),
    "MCS-R002": OWASPMapping((LLM01,), (ASI01,)),
    "MCS-R003": OWASPMapping((LLM06,), (ASI02,)),
    "MCS-R004": OWASPMapping((LLM06,), (ASI03,)),
    "MCS-R005": OWASPMapping((LLM06,), (ASI05,)),
    # Maintenance phase
    "MCS-M001": OWASPMapping((LLM03,), (ASI04,)),
    "MCS-M002": OWASPMapping((LLM06,), (ASI03,)),
    "MCS-M003": OWASPMapping((LLM03,), (ASI04,)),
}


def get_owasp_mapping(rule_id: str) -> OWASPMapping:
    """Look up the OWASP mapping for a given rule ID."""
    return RULE_OWASP.get(rule_id, OWASPMapping())
