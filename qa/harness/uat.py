"""Close a UAT run: check the guide against what ran, render it, publish figures.

A run fails when a page references a figure the run did not produce, or when
a marked step on a page was never executed. The bundle gets `guide/`: every
page with its images pointing at this run's `shots/`, so the proof reads as
the guide as executed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .guide import load
from .journey import Journey

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"


def finish(
    journeys: list[Journey], out: Path, keyword: str | None, publish: bool
) -> list[str]:
    errors: list[str] = []
    ran = {j.page.stem: set(j.ran) for j in journeys}
    documentation_only: dict[str, list[int]] = {}
    (out / "guide").mkdir(exist_ok=True)
    for path in sorted(GUIDE.glob("*.md")):
        page = load(path)
        documentation_only[path.name] = page.unmarked
        if not keyword:
            missing_steps = sorted(set(page.steps) - ran.get(page.stem, set()))
            errors += [f"{path.name}: step {s} never ran" for s in missing_steps]
            for fig in page.figures:
                if not (out / "shots" / fig.removeprefix("img/")).exists():
                    errors.append(f"{path.name}: figure {fig} not produced by this run")
        text = path.read_text().replace("](img/", "](../shots/")
        (out / "guide" / path.name).write_text(text)
    _write_manifest_note(out, documentation_only)
    if publish and not errors:
        _publish(out)
    return errors


def _write_manifest_note(out: Path, documentation_only: dict[str, list[int]]) -> None:
    lines = ["# Shell blocks not executed by this run", ""]
    lines += [
        "Unmarked blocks are documentation only (for example a build or install command the run replaces with --bins).",
        "",
    ]
    for name, at in documentation_only.items():
        lines.append(
            f"- {name}: {', '.join(f'line {n}' for n in at) if at else 'none'}"
        )
    (out / "guide" / "NOT-EXECUTED.md").write_text("\n".join(lines) + "\n")


def _publish(out: Path) -> None:
    """Replace docs/guide/img with exactly the figures the guide references."""
    img = GUIDE / "img"
    referenced = {
        fig.removeprefix("img/") for p in GUIDE.glob("*.md") for fig in load(p).figures
    }
    if img.exists():
        shutil.rmtree(img)
    for rel in sorted(referenced):
        dest = img / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / "shots" / rel, dest)
