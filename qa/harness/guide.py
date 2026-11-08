"""Read an executable guide page: its marked steps, unmarked blocks and figures.

A fenced shell block directly after `<!-- uat:step NAME -->` is a step the UAT
runs verbatim. `<!-- uat:step NAME bg -->` marks a long-running process.
Shell blocks without a marker are documentation only; a run lists them so the
report never implies they were executed. Figures are ordinary Markdown images
under `img/<page>/`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MARKER = re.compile(r"<!--\s*uat:step\s+([a-z0-9][a-z0-9-]*)((?:\s+[a-z]+)*)\s*-->")
FENCE = re.compile(r"^```(\w*)\s*$")
FIGURE = re.compile(r"!\[[^\]]*\]\((img/[^)\s]+)\)")
SHELLS = {"sh", "bash", "shell", "console"}


class GuideError(Exception):
    pass


@dataclass
class Step:
    name: str
    code: str
    line: int
    background: bool = False


@dataclass
class Page:
    path: Path
    steps: dict[str, Step] = field(default_factory=dict)
    unmarked: list[int] = field(default_factory=list)
    figures: list[str] = field(default_factory=list)

    @property
    def stem(self) -> str:
        return self.path.stem

    def step(self, name: str) -> Step:
        try:
            return self.steps[name]
        except KeyError:
            raise GuideError(f"{self.path.name}: no step {name!r}") from None


def load(path: Path) -> Page:
    page = Page(path)
    lines = path.read_text().splitlines()
    pending: tuple[str, bool, int] | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        marker = MARKER.search(line)
        if marker:
            flags = marker.group(2).split()
            unknown = set(flags) - {"bg"}
            if unknown:
                raise GuideError(
                    f"{path.name}:{i + 1}: unknown step flag {sorted(unknown)}"
                )
            pending = (marker.group(1), "bg" in flags, i + 1)
            i += 1
            continue
        fence = FENCE.match(line)
        if fence:
            end = next(
                (j for j in range(i + 1, len(lines)) if lines[j].startswith("```")),
                None,
            )
            if end is None:
                raise GuideError(f"{path.name}:{i + 1}: unclosed code block")
            body = "\n".join(lines[i + 1 : end]) + "\n"
            if pending:
                name, bg, at = pending
                if fence.group(1) not in SHELLS:
                    raise GuideError(
                        f"{path.name}:{at}: step {name} is not a shell block"
                    )
                if name in page.steps:
                    raise GuideError(f"{path.name}:{at}: duplicate step {name}")
                page.steps[name] = Step(name, body, at, bg)
            elif fence.group(1) in SHELLS:
                page.unmarked.append(i + 1)
            pending = None
            i = end + 1
            continue
        if pending and line.strip():
            raise GuideError(
                f"{path.name}:{pending[2]}: step {pending[0]} is not followed by a code block"
            )
        page.figures += FIGURE.findall(line)
        i += 1
    if pending:
        raise GuideError(
            f"{path.name}:{pending[2]}: step {pending[0]} has no code block"
        )
    return page
