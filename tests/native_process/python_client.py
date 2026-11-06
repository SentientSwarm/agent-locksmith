"""Pinned independent Python client against the actual daemon's zero-authority API."""
import asyncio
import json
import os
import ssl
import socket
import traceback
from urllib.parse import urlsplit

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError


async def exercise() -> None:
    context = ssl.create_default_context(cadata=os.environ["PROOF_CA"])
    url = urlsplit(os.environ["PROOF_URL"])
    with socket.create_connection((url.hostname, url.port), timeout=5) as tcp:
        with context.wrap_socket(tcp, server_hostname=url.hostname):
            pass
    async with httpx2.AsyncClient(verify=context, trust_env=False,
            headers={"Authorization": os.environ["PROOF_AGENT_HEADER"]}) as http:
        async with streamable_http_client(os.environ["PROOF_URL"], http_client=http) as streams:
            async with ClientSession(*streams, read_timeout_seconds=5) as client:
                init = await client.initialize()
                print(json.dumps({"step": "initialized"}))
                assert init.protocol_version == "2025-11-25"
                assert (await client.list_tools()).tools == []
                print(json.dumps({"step": "listed"}))
                await client.send_ping()
                try:
                    await client.call_tool("unapproved", {})
                except MCPError as error:
                    assert error.error.code == -32050
                    assert error.error.data["code"] == "tool_not_approved"
                else:
                    raise AssertionError("unapproved tool succeeded")
    print(json.dumps({"client": "mcp-python-2.3.0", "tls_verified": True,
                      "initialize_list_ping_denial_close": "PASS"}))


if __name__ == "__main__":
    try:
        asyncio.run(exercise())
    except Exception as error:
        errors = list(error.exceptions) if isinstance(error, BaseExceptionGroup) else [error]
        while any(isinstance(e, BaseExceptionGroup) for e in errors):
            errors = [child for e in errors for child in (e.exceptions if isinstance(e, BaseExceptionGroup) else [e])]
        for e in list(errors):
            cause = e.__cause__
            while cause is not None:
                errors.append(cause)
                cause = cause.__cause__
        print(json.dumps({"failure_class": type(error).__name__, "causes": [
            {"class": type(e).__name__, "verification": getattr(e, "verify_message", None), "frames": [(os.path.basename(t.filename), t.lineno) for t in traceback.extract_tb(e.__traceback__)]}
            for e in errors]}))
        raise SystemExit(1) from None
