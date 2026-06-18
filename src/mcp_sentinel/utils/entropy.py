"""Shannon entropy calculation for credential detection."""

from __future__ import annotations
import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string. Higher values = more random."""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
    """Check if a string has high entropy (likely a secret/token/key)."""
    if len(data) < 16:
        return False
    return shannon_entropy(data) >= threshold
