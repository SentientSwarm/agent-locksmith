"""Doc citations in code stay true (AGENT-296).

QA cases, tests and source cite the docs they check. A line citation (the
file name, a colon and a line number) drifts silently with every edit above
it, so citations to living docs name a heading instead
(`docs/reference/cli-reference.md#exit-codes`), and this test fails when a
cited heading is gone. The frozen archive keeps its line citations.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Bare names that only the frozen archive still holds.
ARCHIVED = {"SPEC.md", "PRD.md"}
LINE = re.compile(r"([A-Za-z0-9_./-]+\.md):\d+")
# A bare line range left after an anchor or a closing parenthesis.
FRAGMENT = re.compile(r"\.md#[A-Za-z0-9_-]+ and \d+(?:-\d+)?\b|\) and \d{2,4}(?:-\d{2,4})? \(")
# QA cases also wrote ranges out as the word "line" or "lines" and a number;
# in tests and source that wording describes code, not docs.
WRITTEN = re.compile(r"\blines? \d+(?:-\d+)?\b")
ANCHOR = re.compile(r"([A-Za-z0-9_./-]+\.md)#([A-Za-z0-9_-]+)")
FENCE = re.compile(r"^(```+|~~~+)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def slug(text):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")


def anchors(path):
    """Every heading anchor in a Markdown file, numbered as GitHub numbers repeats."""
    seen, out, fence = {}, set(), None
    for line in path.read_text().splitlines():
        m = FENCE.match(line)
        if m:
            if fence is None:
                fence = m.group(1)[:3]
            elif line.startswith(fence):
                fence = None
            continue
        h = None if fence else HEADING.match(line)
        if h:
            base = slug(h.group(2))
            k = seen.get(base, 0)
            seen[base] = k + 1
            out.add(base if k == 0 else f"{base}-{k}")
    return out


def citing_files():
    listed = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "qa", "tests", "src"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    return [ROOT / f for f in listed if f.endswith((".py", ".rs"))]


def citations(pattern):
    for f in citing_files():
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            for m in pattern.finditer(line):
                yield f.relative_to(ROOT), n, m


def test_living_docs_are_cited_by_heading_not_line():
    stale = [
        f"{f}:{n}: {m.group(0)}"
        for f, n, m in citations(LINE)
        if not m.group(1).startswith("docs/archive/") and Path(m.group(1)).name not in ARCHIVED
    ]
    stale += [f"{f}:{n}: {m.group(0)}" for f, n, m in citations(FRAGMENT)]
    stale += [f"{f}:{n}: {m.group(0)}" for f, n, m in citations(WRITTEN) if f.parts[0] == "qa"]
    assert not stale, "cite a heading (path, '#', anchor), not a line:\n" + "\n".join(stale)


def test_every_cited_heading_exists():
    cache, missing = {}, []
    for f, n, m in citations(ANCHOR):
        # A relative link resolves from the citing file; a path from the root.
        near = (ROOT / f).parent / m.group(1)
        doc = near if m.group(1).startswith(".") and near.is_file() else ROOT / m.group(1)
        if not doc.is_file():
            missing.append(f"{f}:{n}: {m.group(1)} does not exist")
            continue
        if doc not in cache:
            cache[doc] = anchors(doc)
        if m.group(2) not in cache[doc]:
            missing.append(f"{f}:{n}: {m.group(0)} names no heading")
    assert not missing, "\n".join(missing)


def test_slug_matches_github():
    assert slug("Exit codes (SPEC §4.7.2)") == "exit-codes-spec-472"
    assert slug("`agent` — agent management (operator)") == "agent--agent-management-operator"
