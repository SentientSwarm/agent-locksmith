"""Shared ADM setup steps, driven only through the CLI and the admin socket."""

from __future__ import annotations

from .adm_uds import uds

# Wrong credentials that stay short so they never resemble a real wire token.
BAD_OPERATOR = "lkop_qawrong.nope"
BAD_AGENT = "lk_qawrong.nope"


def register(t, name: str, allowlist: str | None = None) -> dict:
    """Operator-registers an agent; returns {id, token}."""
    args = ["agent", "register", "--name", name]
    if allowlist:
        args += ["--allowlist", allowlist]
    reg = t.cli(*args)
    assert reg.code == 0, reg.err
    return {"id": reg.json["public_id"], "token": reg.json["token"], "name": name}


def mint(t, *flags: str) -> dict:
    """Mints a bootstrap token; returns the CLI JSON (public_id, token, scope)."""
    out = t.cli("bootstrap", "mint", *flags)
    assert out.code == 0, out.err
    return out.json


def self_register(t, bootstrap_token: str, name: str):
    """Agent self-registration over the admin socket (no CLI command exists)."""
    return uds(
        t,
        "POST",
        "/admin/agent/register",
        body={"bootstrap_token": bootstrap_token, "name": name},
    )


def wrong_secret(token: str) -> str:
    """Same namespace and public_id, a well-formed but different secret.

    Never printed: it only travels in request headers, which are not recorded.
    """
    prefix, _, secret = token.partition(".")
    # Change only leading characters: the final base64url character carries
    # padding bits, so editing it could make the token malformed instead.
    flipped = "".join("B" if c == "A" else "A" for c in secret[:8]) + secret[8:]
    return f"{prefix}.{flipped}"


def agent_names(t, include_revoked: bool = False) -> list[str]:
    args = ["agent", "list"] + (["--include-revoked"] if include_revoked else [])
    out = t.cli(*args)
    assert out.code == 0, out.err
    return [a["name"] for a in out.json]
