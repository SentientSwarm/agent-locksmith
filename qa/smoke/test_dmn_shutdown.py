"""Graceful shutdown and the drain window (docs/v2/runbooks/m1-inference-hardening.md section 6).

A slow loopback upstream holds a proxied request open while the test signals
the daemon, so the request is provably in flight.
"""

import signal
import threading
import time

import pytest

from fakes.dmn_slow import BODY, SlowUpstream
from fakes.dmn_support import wait_for

case = pytest.mark.case
DRAIN = "beh.shutdown.drain"
WINDOW = 5
MARGIN = 2.5


@pytest.fixture(scope="module")
def slow():
    upstream = SlowUpstream()
    yield upstream
    upstream.close()


def prepare(t, slow) -> str:
    put = t.cli(
        "tool",
        "put",
        "slow",
        "--upstream",
        slow.url,
        "--auth",
        "none",
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
    reg = t.cli("agent", "register", "--name", "dmn-drain", "--allowlist", "slow")
    assert reg.code == 0, reg.err
    bind = t.cli("agent", "set-credential", reg.json["public_id"], "slow", "--no-auth")
    assert bind.code == 0, bind.err
    return reg.json["token"]


@pytest.fixture(scope="module")
def drain(target_factory, slow):
    t = target_factory(
        label="dmn-drain",
        upstream=False,
        config={"shutdown": {"drain_window_seconds": WINDOW}},
    )
    t.dmn_token = prepare(t, slow)
    return t


def in_flight(t, slow, delay: float) -> tuple[threading.Thread, list]:
    """Start a proxied request that the upstream holds for `delay` seconds; wait until it arrives."""
    outcome: list = []
    seen = slow.received

    def run():
        try:
            outcome.append(
                t.http("GET", f"/api/slow/delay/{delay}", token=t.dmn_token, timeout=30)
            )
        except OSError as err:
            outcome.append(err)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    assert wait_for(lambda: slow.received > seen, timeout=10), (
        "request never reached the slow upstream"
    )
    return worker, outcome


def timed_stop(t, sig=signal.SIGTERM) -> tuple[int, float]:
    started = time.monotonic()
    code = t.stop(sig, timeout=WINDOW + 15)
    return code, time.monotonic() - started


@case("SMK-DMN-050", area="DMN", kind="positive", covers=[DRAIN])
def test_in_flight_request_completes_within_drain_window(drain, slow):
    """m1-inference-hardening.md:145,171 and config.example.yaml:66-70: on SIGTERM the daemon waits up
    to drain_window_seconds; a request that finishes within the window COMPLETES; clean exit."""
    worker, outcome = in_flight(drain, slow, 2)
    code, elapsed = timed_stop(drain)
    worker.join(10)
    try:
        assert code == 0, f"exit {code} after SIGTERM"
        assert elapsed <= WINDOW + MARGIN, (
            f"stop took {elapsed:.1f}s with a {WINDOW}s window"
        )
        assert outcome and not isinstance(outcome[0], Exception), (
            f"in-flight request failed: {outcome}"
        )
        assert outcome[0].status == 200 and outcome[0].text == BODY.decode()
    finally:
        drain.start()


@case("SMK-DMN-051", area="DMN", kind="positive", covers=[DRAIN])
def test_idle_sigterm_exits_zero_promptly(drain):
    """m1-inference-hardening.md:145-163: SIGTERM (systemctl stop) shuts down cleanly; the window
    caps waiting for in-flight work, so an idle daemon exits 0 well inside it."""
    code, elapsed = timed_stop(drain)
    try:
        assert code == 0
        assert elapsed < WINDOW, f"idle stop took {elapsed:.1f}s"
        assert any(
            e.get("fields", {}).get("message") == "clean shutdown complete"
            for e in drain.log_events()
        )
    finally:
        drain.start()


@case("SMK-DMN-052", area="DMN", kind="positive", covers=[DRAIN])
def test_sigint_exits_zero(drain):
    """m1-inference-hardening.md:145 and config.example.yaml:66: graceful shutdown on SIGINT as well as SIGTERM."""
    code, elapsed = timed_stop(drain, signal.SIGINT)
    try:
        assert code == 0
        assert elapsed < WINDOW
    finally:
        drain.start()


@case("SMK-DMN-053", area="DMN", kind="corner", covers=[DRAIN])
def test_request_longer_than_window_does_not_hold_shutdown(target_factory, slow):
    """m1-inference-hardening.md:171-172 and config.example.yaml:66-68 (in-flight requests get up to the
    window "before the listener is forcibly closed"): a request that does not finish within the window does not
    complete; the listener closes at the window instead of waiting for it."""
    t = target_factory(
        label="dmn-drain-short",
        upstream=False,
        config={"shutdown": {"drain_window_seconds": 1}},
    )
    t.dmn_token = prepare(t, slow)
    worker, outcome = in_flight(t, slow, 8)
    _code, elapsed = timed_stop(t)
    worker.join(15)
    assert elapsed <= 1 + MARGIN, f"stop took {elapsed:.1f}s with a 1s window"
    got = outcome[0] if outcome else None
    assert not (
        got is not None
        and not isinstance(got, Exception)
        and got.status == 200
        and got.text == BODY.decode()
    ), "the agent received a complete response after the window"
