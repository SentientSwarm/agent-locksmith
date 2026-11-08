"""Disposable native tool receiver; observes committed audit before each effect."""

import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import threading

source = Path(__file__).parents[1] / "native_preparation" / "receiver.py"
spec = importlib.util.spec_from_file_location("observation_receiver", source)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.directory = Path(sys.argv[1])
base.lock = threading.Lock()
base.counts = {}
original_result = base.result_for
original_change = base.change


def tools(method: str) -> dict | None:
    manifest = base.directory / "manifest.json"
    if method == "tools/list" and manifest.exists():
        return json.loads(manifest.read_text())
    result = original_result(method)
    if method == "tools/list":
        result["tools"][0]["outputSchema"] = {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "required": ["account"],
            "additionalProperties": False,
        }
    return result


class Handler(base.Handler):
    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        message = json.loads(raw)
        behavior = json.loads((base.directory / "behavior.json").read_text())
        if message["method"] == "initialize" and behavior.get("prepare_hold"):
            base.hold(behavior["prepare_hold"])
        if message["method"] == "tools/list" and behavior.get("mode") in ("policy-sse-held", "policy-sse-notification"):
            result = {"jsonrpc": "2.0", "id": message["id"], "result": tools("tools/list")}
            event = b"data: " + json.dumps(result).encode() + b"\n\n"
            if behavior["mode"] == "policy-sse-notification":
                event = b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n' + event
                self.reply(200, event, sse=True)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.send_header("Mcp-Session-Id", "fixture-session")
                self.end_headers()
                self.wfile.write(event)
                self.wfile.flush()
                base.write(base.directory / "held-sse-sent.json", True)
                base.hold("policy-sse")
                self.close_connection = True
            return
        if message["method"] != "tools/call":
            import io

            self.rfile = io.BytesIO(raw)
            super().do_POST()
            return
        behavior = json.loads((base.directory / "behavior.json").read_text())
        authorization = self.headers.get("Authorization", "")
        self.observed_arguments = message["params"]["arguments"]
        account = {
            "Bearer fixture-account-x": "X",
            "Bearer fixture-account-y": "Y",
            "": "None",
        }.get(authorization, "invalid")
        self.effect(account)
        if behavior.get("call_hold"):
            base.hold(behavior["call_hold"])
        value = self.result(account, authorization, behavior)
        response = {"jsonrpc": "2.0", "id": message["id"], "result": value}
        if behavior.get("call_mode") == "wrong-id":
            response["id"] = 999
        encoded(self, response, behavior.get("call_mode"), authorization)

    def effect(self, account: str) -> None:
        with sqlite3.connect(base.directory / "state.db") as db:
            rows = db.execute(
                "SELECT details FROM audit WHERE event='mcp_admitted'"
            ).fetchall()
        with base.lock:
            path = base.directory / "effects.json"
            effects = json.loads(path.read_text()) if path.exists() else []
            effects.append({"account": account, "committed": len(rows)})
            if (base.directory / "policy-record-arguments").exists():
                effects[-1]["arguments"] = self.observed_arguments
            base.write(path, effects)

    def result(self, account: str, authorization: str, behavior: dict) -> dict:
        result = {
            "content": [{"type": "text", "text": account}],
            "structuredContent": {"account": account},
            "isError": False,
        }
        mode = behavior.get("call_mode")
        token = authorization.removeprefix("Bearer ")
        if mode == "escaped-key":
            result["structuredContent"] = {token: "value"}
        if mode == "structured-echo":
            result["structuredContent"] = {"account": token}
        if mode == "escaped-text":
            result["content"][0]["text"] = token
        if mode == "tool-error":
            result["isError"] = True
            result.pop("structuredContent")
        if mode == "bad-output":
            result["structuredContent"] = {"unexpected": True}
        if mode == "resource":
            result["content"] = [
                {"type": "resource_link", "uri": "https://never.invalid"}
            ]
        if mode == "echo":
            result["content"][0]["text"] = authorization.removeprefix("Bearer ")
        if mode == "oversize":
            result["content"][0]["text"] = "x" * 262145
        return result


def encoded(handler: Handler, response: dict, mode: str, authorization: str) -> None:
    token = authorization.removeprefix("Bearer ")
    if mode == "rpc-error":
        response.pop("result")
        response["error"] = {"code": -32000, "message": token}
    raw = json.dumps(response)
    if mode in ("escaped-text", "escaped-key"):
        raw = raw.replace(token, "".join(f"\\u{ord(c):04x}" for c in token))
    if mode in ("duplicate-json", "duplicate-sse"):
        raw = raw.replace('"isError": false', '"isError":false,"isError":false')
    if mode == "duplicate-sse":
        raw = "data: " + raw + "\n\n"
    handler.reply(200, raw.encode(), sse=mode == "duplicate-sse")


def change(result: dict, mode: str, request_id: int, authorization: str) -> None:
    if mode == "policy-pages":
        pages = json.loads((base.directory / "pages.json").read_text())
        result.clear()
        result.update(pages[request_id - 2])
        return
    if result.get("tools"):
        original_change(result, mode, request_id, authorization)


base.change = change
base.result_for = tools
base.Handler = Handler
base.main(base.directory)
