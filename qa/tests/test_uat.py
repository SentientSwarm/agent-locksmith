"""UAT gate, figure publishing, and the journey's env carry and secret harvest."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from harness import uat
from harness.evidence import Bundle
from harness.guide import load
from harness.journey import Journey
from harness.redact import Canaries

PAGE = """# Page

The demo account is public-demo-value.

<!-- uat:step one -->
```sh
export DEMO_TOKEN=public-demo-value
export API_TOKEN="private-value-$((1000 + 234))"
export CARRIED=yes
cd "$HOME"
mkdir -p sub && cd sub
```

![One](img/page/one.svg)

<!-- uat:step two -->
```sh
echo "$CARRIED $PINNED $(basename "$PWD")"
echo '{"access_token": "field-secret-5678"}'
```

![Two](img/page/two.svg)
"""


@pytest.fixture
def guide(tmp_path):
    root = tmp_path / "guide"
    root.mkdir()
    (root / "page.md").write_text(PAGE)
    return root


def ran(guide, *steps):
    return SimpleNamespace(
        page=load(guide / "page.md"), ran=list(steps), substitutions=[]
    )


def shots(out, *names):
    for name in names:
        path = out / "shots" / "page" / f"{name}.svg"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"<svg>{name}</svg>")


def test_finish_reports_unrun_steps_and_missing_figures(tmp_path, guide):
    out = tmp_path / "out"
    shots(out, "one")
    errors = uat.finish([ran(guide, "one")], out, None, guide)
    assert errors == [
        "page.md: step two never ran",
        "page.md: figure img/page/two.svg not produced by this run",
    ]
    assert (out / "guide" / "NOT-EXECUTED.md").exists()
    assert "](../shots/page/one.svg)" in (out / "guide" / "page.md").read_text()


def test_filtered_run_skips_completeness(tmp_path, guide):
    out = tmp_path / "out"
    out.mkdir()
    assert uat.finish([ran(guide)], out, "test_x", guide) == []


def test_publish_leaves_figures_alone_when_any_is_missing(tmp_path, guide):
    (guide / "img").mkdir()
    (guide / "img" / "keep.svg").write_text("old")
    out = tmp_path / "out"
    shots(out, "one")
    with pytest.raises(FileNotFoundError, match="page/two.svg"):
        uat.publish(out, guide)
    assert (guide / "img" / "keep.svg").read_text() == "old"


def test_publish_replaces_figures_with_exactly_the_referenced_ones(tmp_path, guide):
    (guide / "img").mkdir()
    (guide / "img" / "stale.svg").write_text("old")
    out = tmp_path / "out"
    shots(out, "one", "two", "unreferenced")
    uat.publish(out, guide)
    published = sorted(
        p.relative_to(guide / "img").as_posix() for p in (guide / "img").rglob("*.svg")
    )
    assert published == ["page/one.svg", "page/two.svg"]


@pytest.fixture
def journey(tmp_path, guide):
    bins = tmp_path / "bins"
    bins.mkdir()
    canaries = Canaries()
    j = Journey(
        load(guide / "page.md"),
        bins,
        Bundle(tmp_path / "out", canaries),
        canaries,
        {"PINNED": "pin"},
    )
    yield j
    j.close()


def test_steps_carry_env_and_directory_and_pins_win(journey):
    journey.run("one", shot=False)
    out = journey.run("two", shot=False).out
    assert out.splitlines()[0] == "yes pin sub"


def test_pins_override_a_step_that_exports_them(journey):
    journey._bash("export PINNED=changed", 10, carry=True)
    assert journey.var("PINNED") == "pin"


def test_secret_env_and_fields_become_canaries_unless_public(journey):
    journey.run("one", shot=False)
    journey.run("two", shot=False)
    labels = journey.canaries.labels()
    assert "env-api_token" in labels
    assert "field-access_token" in labels
    assert "env-demo_token" not in labels  # printed as a whole token in the guide
    assert journey.canaries.redact("private-value-1234") != "private-value-1234"


def test_public_exemption_needs_a_whole_token(journey):
    assert journey._is_public("public-demo-value")
    assert not journey._is_public("demo-value")  # only part of a token in the guide


def test_secret_file_registers_its_contents(journey, tmp_path):
    home = tmp_path / "lshome"
    home.mkdir()
    (home / "k.key").write_text("c2VhbGluZy1rZXktdmFsdWU=\n")
    journey.env["LOCKSMITH_HOME"] = str(home)
    journey.secret_file("k.key", "sealing")
    assert "sealing" in journey.canaries.labels()


def test_publish_requires_a_complete_uat_run():
    import run

    with pytest.raises(SystemExit):
        run.parse_args(
            [
                "--bins",
                "b",
                "--out",
                "o",
                "--suite",
                "uat",
                "--publish-figures",
                "-k",
                "x",
            ]
        )
    with pytest.raises(SystemExit):
        run.parse_args(["--bins", "b", "--out", "o", "--publish-figures"])
    assert run.parse_args(
        ["--bins", "b", "--out", "o", "--suite", "uat", "--publish-figures"]
    ).publish_figures


def test_daemon_ready_needs_a_listening_admin_socket(tmp_path):
    stale = tmp_path / "admin.sock"
    stale.write_text("")  # a file left behind by an earlier daemon is not a socket
    j = SimpleNamespace(
        var=lambda name: str(stale) if name == "LOCKSMITH_SOCKET" else ""
    )
    with pytest.raises(OSError):
        uat.daemon_ready(j)
    assert Path(stale).exists()
