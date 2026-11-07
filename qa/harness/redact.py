"""Secret canaries and the evidence-bundle redaction scanner.

Findings name the file and a label, never the matched value.
"""
from __future__ import annotations

import re
from pathlib import Path

MIN_CANARY = 8

# Shapes that must never appear in kept evidence, whatever registered them.
SHAPES: list[tuple[str, re.Pattern[bytes]]] = [
    ("locksmith-wire-token", re.compile(rb"\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}\b")),
    ("bearer-header", re.compile(rb"Bearer [A-Za-z0-9._~+/=-]{20,}")),
    ("argon2-hash", re.compile(rb"\$argon2(id|i|d)\$")),
    ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("oauth-code-or-state", re.compile(rb"[?&](code|state)=[^&\s]+")),
]


class Canaries:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def add(self, value: str | None, label: str) -> None:
        if value and len(value) >= MIN_CANARY:
            self._values[value] = label

    def labels(self) -> list[str]:
        return sorted(set(self._values.values()))

    def redact(self, text: str) -> str:
        for value in sorted(self._values, key=len, reverse=True):
            text = text.replace(value, f"<redacted:{self._values[value]}>")
        return text

    def items(self) -> list[tuple[bytes, str]]:
        return [(v.encode(), label) for v, label in self._values.items()]


def scan_bundle(root: Path, canaries: Canaries) -> list[str]:
    findings: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        data = path.read_bytes()
        rel = path.relative_to(root).as_posix()
        labels = {label for value, label in canaries.items() if value in data}
        labels |= {name for name, pattern in SHAPES if pattern.search(data)}
        findings += [f"{rel}: {label}" for label in sorted(labels)]
    return findings
