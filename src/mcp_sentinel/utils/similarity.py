"""String similarity metrics for namespace typosquatting detection."""

from __future__ import annotations


def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein (edit) distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insert = prev[j + 1] + 1
            delete = curr[j] + 1
            sub = prev[j] + (0 if c1 == c2 else 1)
            curr.append(min(insert, delete, sub))
        prev = curr
    return prev[-1]


def jaro_winkler(s1: str, s2: str, scaling: float = 0.1) -> float:
    """Compute Jaro-Winkler similarity (0.0 to 1.0)."""
    s1, s2 = s1.lower(), s2.lower()
    if s1 == s2:
        return 1.0

    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_dist = max(len1, len2) // 2 - 1
    if match_dist < 0:
        match_dist = 0

    s1_match = [False] * len1
    s2_match = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if not s2_match[j] and s1[i] == s2[j]:
                s1_match[i] = s2_match[j] = True
                matches += 1
                break

    if matches == 0:
        return 0.0

    transpositions = 0
    k = 0
    for i in range(len1):
        if s1_match[i]:
            while not s2_match[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1

    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return jaro + prefix * scaling * (1 - jaro)


def is_typosquat(name: str, known: list[str], threshold: float = 0.85) -> list[tuple[str, float, int]]:
    """Check if name is a potential typosquat of any known name.

    Returns list of (known_name, jaro_winkler_score, levenshtein_distance).
    """
    results = []
    name_lower = name.lower()
    for known_name in known:
        if name_lower == known_name.lower():
            continue  # exact match is not typosquatting
        jw = jaro_winkler(name_lower, known_name.lower())
        if jw >= threshold:
            ld = levenshtein(name_lower, known_name.lower())
            results.append((known_name, jw, ld))
    results.sort(key=lambda x: (-x[1], x[2]))
    return results
