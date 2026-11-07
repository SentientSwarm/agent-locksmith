"""Surface contract: what the product exposes, checked against the source.

Every route literal in the source and every CLI leaf command must have a
contract entry (fail closed). Coverage maps case results onto entries.
"""
from __future__ import annotations

import datetime as dt
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .status import CaseRecord, Status

ROUTE_SOURCES = ("src",)
METHOD_RE = re.compile(r"(?:^|[^A-Za-z0-9_])(get|post|put|patch|delete|any)\(")
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


class ContractError(Exception):
    pass


@dataclass
class Contract:
    routes: list[dict]
    cli: list[dict]
    behaviours: list[dict]
    journeys: list[dict]
    floors: dict[str, int]
    known_gaps: dict[str, dict] = field(default_factory=dict)

    def entries(self) -> list[dict]:
        return self.routes + self.cli + self.behaviours + self.journeys


def load(path: Path) -> Contract:
    data = yaml.safe_load(path.read_text())
    if data.get("version") != 1:
        raise ContractError("surface.yaml version must be 1")
    contract = Contract(
        routes=data.get("routes", []),
        cli=data.get("cli", []),
        behaviours=data.get("behaviours", []),
        journeys=data.get("journeys", []),
        floors=data.get("floors", {}),
        known_gaps={g["id"]: g for g in data.get("known_gaps", [])},
    )
    ids = Counter(e["id"] for e in contract.entries())
    dupes = sorted(i for i, n in ids.items() if n > 1)
    if dupes:
        raise ContractError(f"duplicate contract ids: {dupes}")
    for gap in contract.known_gaps.values():
        missing = {"reason", "ticket", "expires"} - gap.keys()
        if missing:
            raise ContractError(f"known gap {gap['id']} lacks {sorted(missing)}")
        if gap["id"] not in ids:
            raise ContractError(f"known gap {gap['id']} names no contract entry")
    return contract


def _calls(text: str, opener: str):
    """Yield (line, argument text) for each `.<opener>(` call, balancing parens."""
    for match in re.finditer(re.escape(f".{opener}("), text):
        depth, i = 1, match.end()
        while depth and i < len(text):
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        if depth:
            raise ContractError(f"unbalanced .{opener}( at offset {match.start()}")
        yield text.count("\n", 0, match.start()) + 1, text[match.end() : i - 1]


def source_routes(repo: Path) -> Counter:
    """Multiset of (file, route literal, METHOD) declared in product source."""
    found: Counter = Counter()
    for root in ROUTE_SOURCES:
        for path in sorted((repo / root).rglob("*.rs")):
            text = path.read_text()
            rel = path.relative_to(repo).as_posix()
            for line, args in _calls(text, "route"):
                literal = STRING_RE.search(args)
                methods = METHOD_RE.findall(args)
                if not literal or not methods:
                    raise ContractError(f"{rel}:{line}: cannot parse route declaration")
                for method in methods:
                    found[(rel, literal.group(1), method.upper())] += 1
            for _line, _args in _calls(text, "fallback"):
                found[(rel, "*fallback*", "ANY")] += 1
    return found


def cli_leaves(locksmith: Path) -> set[str]:
    """Walk `locksmith ... --help` and return space-joined leaf command paths."""

    def subcommands(path: list[str]) -> list[str]:
        out = subprocess.run([str(locksmith), *path, "--help"], capture_output=True, text=True, check=True).stdout
        names, in_block = [], False
        for line in out.splitlines():
            if line.strip() == "Commands:":
                in_block = True
                continue
            if in_block:
                if not line.startswith("  "):
                    break
                name = line.split()[0]
                if name != "help":
                    names.append(name)
        return names

    leaves: set[str] = set()
    stack: list[list[str]] = [[]]
    while stack:
        path = stack.pop()
        children = subcommands(path)
        if not children and path:
            leaves.add(" ".join(path))
        stack += [path + [c] for c in children]
    return leaves


def check_source(contract: Contract, repo: Path, locksmith: Path | None) -> list[str]:
    errors: list[str] = []
    declared: Counter = Counter()
    for r in contract.routes:
        src = r.get("source")
        if not src:
            errors.append(f"route {r['id']} has no source")
            continue
        declared[(src["file"], src["route"], r["method"])] += 1
    actual = source_routes(repo)
    for key in sorted(set(actual) | set(declared)):
        if actual[key] != declared[key]:
            file, route, method = key
            errors.append(f"route {method} {route} in {file}: source has {actual[key]}, contract has {declared[key]}")
    if locksmith is not None:
        leaves = cli_leaves(locksmith)
        contracted = {c["command"] for c in contract.cli}
        errors += [f"CLI command `locksmith {c}` is not in the contract" for c in sorted(leaves - contracted)]
        errors += [f"contract CLI command `locksmith {c}` does not exist" for c in sorted(contracted - leaves)]
    return errors


def coverage(contract: Contract, records: list[CaseRecord], today: dt.date | None = None) -> dict[str, str]:
    today = today or dt.date.today()
    result: dict[str, str] = {}
    for entry in contract.entries():
        eid = entry["id"]
        covering = [r for r in records if eid in r.covers]
        if entry.get("not_product"):
            result[eid] = Status.NOT_APPLICABLE.value
        elif any(r.status is Status.FAIL for r in covering):
            result[eid] = Status.FAIL.value
        elif _exercised(entry, covering):
            result[eid] = Status.PASS.value
        elif _gap_open(contract.known_gaps.get(eid), today):
            result[eid] = Status.NOT_APPLICABLE.value
        else:
            result[eid] = Status.NOT_EXERCISED.value
    return result


def _exercised(entry: dict, covering: list[CaseRecord]) -> bool:
    passed = [r for r in covering if r.status is Status.PASS]
    if not any(r.kind == "positive" for r in passed):
        return False
    produced = {code for r in passed if r.kind == "refusal" for code in r.codes}
    return set(entry.get("refusals", [])) <= produced


def _gap_open(gap: dict | None, today: dt.date) -> bool:
    if not gap:
        return False
    expires = gap["expires"]
    expires = expires if isinstance(expires, dt.date) else dt.date.fromisoformat(str(expires))
    return today <= expires
