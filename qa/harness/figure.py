"""Guide figures: terminal windows rendered from redacted text, and browser shots.

Terminal figures are drawn from text that has already passed canary
redaction, so a figure can never show more than its transcript.
"""

from __future__ import annotations

import io
from pathlib import Path

WIDTH = 100
MAX_LINES = 40


def prompt_lines(code: str) -> list[str]:
    """Show a step as typed: `$ ` before each command, `> ` inside heredocs."""
    out: list[str] = []
    heredoc: str | None = None
    continued = False
    for line in code.rstrip("\n").splitlines():
        if heredoc is not None:
            out.append(f"> {line}")
            if line.strip() == heredoc:
                heredoc = None
            continue
        out.append(("  " if continued else "$ ") + line)
        continued = line.endswith("\\")
        if "<<" in line:
            tag = line.split("<<", 1)[1].strip().split()[0].strip("'\"-")
            heredoc = tag or None
    return out


def clip(text: str, limit: int = MAX_LINES) -> str:
    lines = text.rstrip("\n").splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    keep = limit - 1
    return "\n".join(
        lines[:keep] + [f"… {len(lines) - keep} more lines in the transcript"]
    )


def terminal(path: Path, title: str, code: str, output: str) -> None:
    """Write an SVG terminal window showing the command and its output."""
    from rich.console import Console
    from rich.text import Text

    console = Console(
        record=True,
        width=WIDTH,
        force_terminal=True,
        color_system="truecolor",
        file=io.StringIO(),
    )
    for line in prompt_lines(code):
        console.print(
            Text(line, style="bold green" if line.startswith("$ ") else "green"),
            overflow="fold",
        )
    if output.strip():
        console.print(Text(clip(output)), overflow="fold")
    path.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(path), title=title)


class Browser:
    """Headless installed Chrome for consent-page screenshots."""

    def __init__(self) -> None:
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(channel="chrome", headless=True)
        self.page = self._browser.new_page(viewport={"width": 1100, "height": 760})

    def shot(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.page.screenshot(path=str(path), full_page=True)

    def close(self) -> None:
        self._browser.close()
        self._pw.stop()
