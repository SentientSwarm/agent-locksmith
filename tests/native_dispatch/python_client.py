"""Positive standard Python SDK consumer for the disposable daemon test."""

import asyncio
import json
import os
import ssl

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def exercise() -> None:
    context = ssl.create_default_context(cadata=os.environ["PROOF_CA"])
    async with httpx2.AsyncClient(
        verify=context,
        trust_env=False,
        headers={"Authorization": os.environ["PROOF_AGENT_HEADER"]},
    ) as http:
        async with streamable_http_client(
            os.environ["PROOF_URL"], http_client=http
        ) as streams:
            async with ClientSession(*streams, read_timeout_seconds=5) as client:
                init = await client.initialize()
                assert init.protocol_version == "2025-11-25"
                listed = await client.list_tools()
                assert [tool.name for tool in listed.tools] == ["read_record"]
                result = await client.call_tool("read_record", {"key": "python-record"})
                assert result.structured_content == {"account": "None"}
                assert not result.is_error
                await client.send_ping()
    print(
        json.dumps({"sdk": "mcp-python-2.3.0", "tls_verified": True, "positive": True})
    )


if __name__ == "__main__":
    asyncio.run(exercise())
