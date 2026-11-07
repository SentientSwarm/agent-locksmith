import pytest


@pytest.fixture(scope="session")
def t1(request):
    plugin = getattr(request.config, "qa_plugin", None)
    if plugin is None:
        pytest.fail("run smoke through qa/run.py, which supplies the QA plugin")
    target = plugin.make_target()
    try:
        target.start()
        yield target
    finally:
        target.close()


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
