"""Close a UAT run: check the guide against what ran, render it, publish figures.

A run fails when a page references a figure the run did not produce, or when
a marked step on a page was never executed. The bundle gets `guide/`: every
page with its images pointing at this run's `shots/`, so the proof reads as
the guide as executed.
"""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

from .guide import load
from .journey import Journey

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"


def port_open(port: str | int) -> bool:
    with socket.create_connection(("127.0.0.1", int(port)), timeout=1):
        return True


def daemon_ready(j: Journey, *ports: str) -> bool:
    """The daemon accepts admin commands: its ports listen and its admin socket accepts.

    The daemon binds the agent port before it opens the database and binds the
    admin socket, so an open port alone does not mean admin commands will work.
    It also leaves the socket file behind on exit, so connect rather than stat.
    """
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(1)
        s.connect(j.var("LOCKSMITH_SOCKET"))
    return all(port_open(j.var(p)) for p in ports)


def finish(
    journeys: list[Journey], out: Path, keyword: str | None, guide: Path = GUIDE
) -> list[str]:
    errors: list[str] = []
    ran = {j.page.stem: set(j.ran) for j in journeys}
    documentation_only: dict[str, list[int]] = {}
    (out / "guide").mkdir(exist_ok=True)
    for path in sorted(guide.glob("*.md")):
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
    subs = {f"{j.page.path.name}: {note}" for j in journeys for note in j.substitutions}
    _write_manifest_note(out, documentation_only, sorted(subs))
    return errors


def _write_manifest_note(
    out: Path, documentation_only: dict[str, list[int]], subs: list[str]
) -> None:
    lines = ["# Shell blocks not executed by this run", ""]
    lines += [
        "Unmarked blocks are documentation only (for example a build or install command the run replaces with --bins).",
        "",
    ]
    for name, at in documentation_only.items():
        lines.append(
            f"- {name}: {', '.join(f'line {n}' for n in at) if at else 'none'}"
        )
    lines += ["", "## Substitutions", "", "What this run stood in for:", ""]
    lines += [f"- {s}" for s in subs] or ["- none"]
    (out / "guide" / "NOT-EXECUTED.md").write_text("\n".join(lines) + "\n")


def publish(out: Path, guide: Path = GUIDE) -> None:
    """Replace `guide`/img with exactly the figures the guide references.

    Call only after a complete run passed its gate and the redaction scan.
    Every source figure is checked before anything is removed.
    """
    img = guide / "img"
    referenced = {
        fig.removeprefix("img/") for p in guide.glob("*.md") for fig in load(p).figures
    }
    missing = sorted(r for r in referenced if not (out / "shots" / r).is_file())
    if missing:
        raise FileNotFoundError(f"figures not in {out / 'shots'}: {', '.join(missing)}")
    if img.exists():
        shutil.rmtree(img)
    for rel in sorted(referenced):
        dest = img / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / "shots" / rel, dest)
