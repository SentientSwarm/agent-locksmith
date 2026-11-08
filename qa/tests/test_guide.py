"""Guide parsing and terminal figure rendering."""

import pytest

from harness.figure import clip, prompt_lines, terminal
from harness.guide import GuideError, load

PAGE = """# Page

<!-- uat:step one -->
```sh
echo one
```

![Figure](img/page/one.svg)

```sh
cargo build
```

<!-- uat:step serve bg -->
```bash
exec server
```

```yaml
not: shell
```
"""


def write(tmp_path, text):
    path = tmp_path / "page.md"
    path.write_text(text)
    return path


def test_marked_unmarked_and_figures(tmp_path):
    page = load(write(tmp_path, PAGE))
    assert list(page.steps) == ["one", "serve"]
    assert page.steps["one"].code == "echo one\n"
    assert page.steps["serve"].background
    assert page.unmarked == [10]
    assert page.figures == ["img/page/one.svg"]


@pytest.mark.parametrize(
    "text, message",
    [
        ("<!-- uat:step a -->\n```yaml\nx: 1\n```\n", "not a shell block"),
        ("<!-- uat:step a -->\nprose\n```sh\nx\n```\n", "not followed by a code block"),
        (
            "<!-- uat:step a -->\n```sh\nx\n```\n<!-- uat:step a -->\n```sh\ny\n```\n",
            "duplicate step",
        ),
        ("<!-- uat:step a fast -->\n```sh\nx\n```\n", "unknown step flag"),
        ("<!-- uat:step a -->\n```sh\nx\n", "unclosed code block"),
        ("<!-- uat:step a -->\n", "has no code block"),
    ],
)
def test_malformed_pages_are_refused(tmp_path, text, message):
    with pytest.raises(GuideError, match=message):
        load(write(tmp_path, text))


def test_prompt_lines_mark_commands_continuations_and_heredocs():
    code = "cat > f <<EOF\na: 1\nEOF\ncurl -fsS \\\n  http://x\necho done\n"
    assert prompt_lines(code) == [
        "$ cat > f <<EOF",
        "> a: 1",
        "> EOF",
        "$ curl -fsS \\",
        "    http://x",
        "$ echo done",
    ]


def test_clip_keeps_long_output_bounded():
    text = "\n".join(str(i) for i in range(100))
    lines = clip(text, limit=10).splitlines()
    assert len(lines) == 10
    assert lines[-1].startswith("… 91 more lines")


def test_terminal_figure_contains_command_and_output(tmp_path):
    path = tmp_path / "f.svg"
    terminal(path, "page: one", "echo hi\n", "hi\n")
    svg = path.read_text()
    assert svg.startswith("<svg")
    # rich writes spaces as non-breaking entities
    assert "page:&#160;one" in svg and "$&#160;echo&#160;hi" in svg
