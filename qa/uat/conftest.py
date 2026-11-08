"""UAT fixtures: one journey per module, over the guide page the module names.

A journey module sets PAGE (a file under docs/guide/) and PORTS (env names
pinned to free ports). Its checkpoints run in file order; once one fails, the
rest of that journey report NOT_EXERCISED instead of failing on stale state.
"""

from pathlib import Path

import pytest

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"


@pytest.fixture(scope="module")
def journey(request):
    plugin = getattr(request.config, "qa_plugin", None)
    if plugin is None:
        pytest.fail(
            "run UAT through qa/run.py --suite uat, which supplies the QA plugin"
        )
    module = request.module
    j = plugin.make_journey(GUIDE / module.PAGE, tuple(getattr(module, "PORTS", ())))
    module._journey = j
    try:
        yield j
    finally:
        j.close()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item):
    outcome = yield
    report = outcome.get_result()
    j = getattr(item.module, "_journey", None)
    if report.failed and j is not None:
        j.failed = True


def pytest_runtest_setup(item):
    j = getattr(item.module, "_journey", None)
    if j is not None and j.failed:
        pytest.skip("an earlier checkpoint in this journey failed")
