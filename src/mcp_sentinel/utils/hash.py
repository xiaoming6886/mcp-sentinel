"""File/content hashing utilities."""

from __future__ import annotations
import hashlib
from pathlib import Path


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Compute the hash of a file's contents."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_string(data: str, algorithm: str = "sha256") -> str:
    """Compute the hash of a string."""
    return hashlib.new(algorithm, data.encode("utf-8")).hexdigest()


def verify_checksum(path: Path, expected: str, algorithm: str = "sha256") -> bool:
    """Verify that a file's hash matches the expected value."""
    actual = hash_file(path, algorithm)
    return actual == expected
