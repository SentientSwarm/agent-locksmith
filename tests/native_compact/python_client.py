"""Ordinary pinned Python SDK: full public schemas before argument construction."""
import asyncio
import json
import os
import ssl
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


def payload(result):
    assert not result.is_error
    assert len(result.content) == 1
    return json.loads(result.content[0].text)


async def main():
    compact = os.environ["PROOF_COMPACT"] == "true"
    all_protected = os.environ["PROOF_ALL"] == "true"
    context = ssl.create_default_context(cadata=os.environ["PROOF_CA"])
    async with httpx2.AsyncClient(verify=context, trust_env=False, headers={"Authorization": os.environ["PROOF_AGENT_HEADER"]}) as http:
        async with streamable_http_client(os.environ["PROOF_URL"], http_client=http) as streams:
            async with ClientSession(*streams, read_timeout_seconds=5) as client:
                await client.initialize()
                listed = await client.list_tools()
                if compact:
                    assert [t.name for t in listed.tools] == ["search", "describe", "invoke"]
                    entry = payload(await client.call_tool("search", {"query": "read"}))["matches"][0]
                    described = payload(await client.call_tool("describe", {"handle": entry["handle"]}))
                    assert described["contract_digest"] == entry["contract_digest"]
                    schema = described["input_schema"]
                else:
                    assert [t.name for t in listed.tools] == ["read_record"]
                    schema = listed.tools[0].input_schema
                assert "workspace" not in schema["properties"]
                assert ("key" not in schema["properties"]) == all_protected
                arguments = {} if all_protected else {"key": "record"}
                if compact:
                    result = await client.call_tool("invoke", {"handle": entry["handle"], "contract_digest": described["contract_digest"], "arguments": arguments})
                else:
                    result = await client.call_tool("read_record", arguments)
                assert not result.is_error
                assert result.content[0].text == os.environ["PROOF_ACCOUNT"]
                await client.send_ping()


if __name__ == "__main__":
    asyncio.run(main())
