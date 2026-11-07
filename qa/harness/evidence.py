"""Evidence bundle: manifest, per-case transcripts, results and report."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .redact import Canaries
from .status import CaseRecord


class Bundle:
    def __init__(self, root: Path, canaries: Canaries) -> None:
        self.root = root
        self.canaries = canaries
        self.manifest: dict = {}
        root.mkdir(parents=True, exist_ok=True)
        self._seq = Counter()

    def write_manifest(self, manifest: dict) -> None:
        self.manifest.update(manifest)
        self._write_json("manifest.json", self.manifest)

    def transcript(self, case_id: str, name: str, text: str) -> str:
        key = (case_id, name)
        self._seq[key] += 1
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        rel = f"cases/{case_id}/{self._seq[key]:02d}-{safe}.txt"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.canaries.redact(text))
        return rel

    def write_results(self, records: list[CaseRecord], gate_result: tuple[bool, list[str]], coverage: dict[str, str]) -> None:
        passed, reasons = gate_result
        data = {
            "cases": [{**r.__dict__, "status": r.status.value} for r in records],
            "gate": {"passed": passed, "reasons": reasons},
            "coverage": coverage,
        }
        self._write_json("results.json", data)
        self._write_report(records, passed, reasons, coverage)

    def _write_report(self, records, passed, reasons, coverage) -> None:
        m = self.manifest
        lines = [
            "# Locksmith QA run",
            "",
            f"- Commit: `{m.get('commit', '?')}` ({'dirty' if m.get('tree_dirty') else 'clean'})",
            f"- Target: {m.get('target', '?')}; mode: {m.get('mode', '?')}; release_ready: {m.get('release_ready', False)}",
            f"- Gate: **{'PASS' if passed else 'FAIL'}**",
            "",
        ]
        lines += [f"  - {r}" for r in reasons]
        lines += ["", "| Case | Area | Kind | Status | Detail |", "|---|---|---|---|---|"]
        for r in records:
            detail = r.detail.replace("|", "\\|").replace("\n", " ")[:200]
            lines.append(f"| {r.id} | {r.area} | {r.kind} | {r.status.value} | {detail} |")
        counts = Counter(coverage.values())
        lines += ["", "## Surface coverage", ""]
        lines += [f"- {k}: {v}" for k, v in sorted(counts.items())]
        (self.root / "report.md").write_text("\n".join(lines) + "\n")

    def _write_json(self, name: str, data) -> None:
        (self.root / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
