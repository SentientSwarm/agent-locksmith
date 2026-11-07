"""Shared smoke fixtures. Every target started here is closed at session end."""

import pytest


def _plugin(request):
    plugin = getattr(request.config, "qa_plugin", None)
    if plugin is None:
        pytest.fail("run smoke through qa/run.py, which supplies the QA plugin")
    return plugin


@pytest.fixture(scope="session")
def target_factory(request):
    """Return start(**LocalTarget kwargs) -> started target; closes all at the end.

    kwargs: config (dict overlay or callable(workdir) -> dict; None values
    delete keys), env (extra daemon environment), label, upstream (bool).
    """
    plugin = _plugin(request)
    started = []

    def start(**kwargs):
        target = plugin.make_target(**kwargs)
        started.append(target)
        target.start()
        return target

    try:
        yield start
    finally:
        for target in started:
            target.close()


@pytest.fixture(scope="session")
def t1(target_factory):
    """The default getting-started daemon (bearer, admin socket, empty catalog)."""
    return target_factory(label="main")


@pytest.fixture(scope="session")
def build(t1):
    return t1.build_info()


@pytest.fixture(scope="session")
def accounts(t1):
    """The getting-started HTTP connection to the reference API."""
    put = t1.cli("tool", "put", "accounts", "--upstream", t1.upstream_url,
                 "--auth", "bearer=SMOKE_X", "--egress", "direct")
    assert put.code == 0, put.err
    return "accounts"
