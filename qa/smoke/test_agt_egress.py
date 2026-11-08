"""Egress routing and upstream TLS trust (docs/user/architecture.md:80-82,
docs/user/cli-reference.md:177, README.md:98-101, config.example.yaml egress_proxy / tls)."""

import shutil
import tempfile
from pathlib import Path

import pytest

from fakes.agt_support import enrol, put_tool
from fakes.agt_upstream import EgressProxy, Upstream, tls_context
from fakes.pki import CA

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
EGRESS = "beh.egress.proxied"
TLS = "beh.tls.upstream-ca"


@pytest.fixture(scope="module")
def eg(target_factory):
    tmp = Path(tempfile.mkdtemp(prefix="agt-pki-"))
    ca = CA.create("qa-agt-upstream-ca")
    leaf = ca.server(("127.0.0.1", "localhost"))
    (tmp / "ca.pem").write_bytes(ca.cert_pem())
    (tmp / "srv.pem").write_bytes(leaf.cert_pem())
    (tmp / "srv.key").write_bytes(leaf.key_pem())
    http_up = Upstream()
    https_up = Upstream(tls_context(str(tmp / "srv.pem"), str(tmp / "srv.key")))
    proxy = EgressProxy()

    def ca_overlay(work: Path) -> dict:
        bundle = work / "upstream-ca.pem"
        bundle.write_bytes(ca.cert_pem())
        return {"egress_proxy": proxy.url, "tls": {"upstream_ca_bundle": str(bundle)}}

    trusted = target_factory(label="agt-egress", upstream=False, config=ca_overlay)
    plain = target_factory(label="agt-egress-noca", upstream=False)
    specs = {
        "agt-via": (f"{http_up.url}/via", "proxied"),
        "agt-direct": (f"{http_up.url}/direct", "direct"),
        "agt-via-tls": (f"{https_up.url}/viatls", "proxied"),
        "agt-tls": (f"{https_up.url}/tls", "direct"),
    }
    for name, (upstream, egress) in specs.items():
        put_tool(trusted, name, upstream, "none", "--egress", egress)
    put_tool(plain, "agt-tls", f"{https_up.url}/tls", "none", "--egress", "direct")
    agent = enrol(
        trusted, "qa-agt-egress", list(specs), {n: ["--no-auth"] for n in specs}
    )
    plain_agent = enrol(plain, "qa-agt-noca", ["agt-tls"], {"agt-tls": ["--no-auth"]})
    yield {
        "t": trusted,
        "plain": plain,
        "agent": agent,
        "plain_agent": plain_agent,
        "http": http_up,
        "https": https_up,
        "proxy": proxy,
    }
    for fake in (http_up, https_up, proxy):
        fake.close()
    shutil.rmtree(tmp, ignore_errors=True)


@case("SMK-AGT-050", area="AGT", kind="positive", covers=[API, EGRESS])
def test_proxied_http_upstream_goes_through_egress_proxy(eg):
    """architecture.md:80-82 + config.example.yaml (egress_proxy: tools with `egress: proxied`
    route through the configured proxy)."""
    t, proxy, up = eg["t"], eg["proxy"], eg["http"]
    seen, before = proxy.count(), up.count("/via")
    resp = t.http("GET", "/api/agt-via/ping?q=1", token=eg["agent"]["token"])
    assert resp.status == 200
    assert proxy.count() == seen + 1
    _method, target = proxy.seen[-1]
    assert (
        target.endswith(f":{up.port}/via/ping?q=1") or target == f"127.0.0.1:{up.port}"
    )
    assert up.count("/via") == before + 1


@case("SMK-AGT-051", area="AGT", kind="corner", covers=[API, EGRESS])
def test_direct_egress_bypasses_proxy(eg):
    """architecture.md:82 `egress: direct` goes straight to upstream; CLAUDE.md "LAN tools use
    egress: direct and bypass the CONNECT proxy"."""
    t, proxy, up = eg["t"], eg["proxy"], eg["http"]
    seen, before = proxy.count(), up.count("/direct")
    resp = t.http("GET", "/api/agt-direct/ping", token=eg["agent"]["token"])
    assert resp.status == 200
    assert up.count("/direct") == before + 1
    assert proxy.count() == seen, "direct egress went through the egress proxy"


@case("SMK-AGT-052", area="AGT", kind="positive", covers=[API, EGRESS, TLS])
def test_proxied_https_upstream_uses_connect(eg):
    """architecture.md:81 `egress: proxied -> HTTP CONNECT through pipelock`; the tunnelled
    upstream is verified with tls.upstream_ca_bundle (README.md:98-101)."""
    t, proxy, up = eg["t"], eg["proxy"], eg["https"]
    seen, before = proxy.count(), up.count("/viatls")
    resp = t.http("GET", "/api/agt-via-tls/ping", token=eg["agent"]["token"])
    assert resp.status == 200
    assert up.count("/viatls") == before + 1
    assert proxy.seen[seen:] == [("CONNECT", f"127.0.0.1:{up.port}")]


@case("SMK-AGT-053", area="AGT", kind="positive", covers=[API, TLS])
def test_private_ca_upstream_trusted_with_bundle(eg):
    """README.md:98-101 + config.example.yaml `tls.upstream_ca_bundle` — the named PEM adds
    a trust root so an HTTPS upstream behind a private CA verifies."""
    t, up = eg["t"], eg["https"]
    before = up.count("/tls")
    resp = t.http("GET", "/api/agt-tls/ping", token=eg["agent"]["token"])
    assert resp.status == 200
    assert resp.text == "ok"
    assert up.count("/tls") == before + 1


@case(
    "SMK-AGT-054",
    area="AGT",
    kind="refusal",
    covers=[API, TLS],
    codes=["upstream_error"],
)
def test_private_ca_upstream_refused_without_bundle(eg):
    """README.md:98-101 + config.example.yaml — webpki roots ignore the system store and
    verification is never disabled: without the bundle the HTTPS upstream is refused
    (wire-contract.md:227 502 upstream_error) and no HTTP request reaches it."""
    t, up = eg["plain"], eg["https"]
    before = up.count("/tls")
    resp = t.http("GET", "/api/agt-tls/ping", token=eg["plain_agent"]["token"])
    assert resp.status == 502
    assert resp.json["error"]["type"] == "upstream_error"
    assert up.count("/tls") == before, (
        "an unverified HTTPS upstream received the request"
    )


@case("SMK-AGT-055", area="AGT", kind="corner", covers=[EGRESS, "cli.tool.put", "cli.tool.get"])
def test_egress_defaults_to_direct(eg):
    """cli-reference.md:177 — `--egress direct|proxied` "Defaults `direct`": a tool put without
    --egress is saved direct and does not route through the egress proxy."""
    t, proxy, up = eg["t"], eg["proxy"], eg["http"]
    put = t.cli("tool", "put", "agt-default-egress", "--upstream", f"{up.url}/dflt", "--auth", "none")
    assert put.code == 0, put.err
    assert t.cli("tool", "get", "agt-default-egress").json["egress"] == "direct"
    agent = enrol(t, "qa-agt-dflt", ["agt-default-egress"], {"agt-default-egress": ["--no-auth"]})
    seen, before = proxy.count(), up.count("/dflt")
    assert t.http("GET", "/api/agt-default-egress/ping", token=agent["token"]).status == 200
    assert up.count("/dflt") == before + 1
    assert proxy.count() == seen, "default egress went through the egress proxy"
